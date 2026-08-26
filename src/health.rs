use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rand::Rng;
use reqwest::redirect::Policy;
use reqwest::Url;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::client::{Client, RecoveryAuthenticationRequired, RecoveryRateLimited};
use crate::config::{HealthCheckConfig, WgConf};
use crate::wg::TunnelRuntime;

const DNS_TYPE_A: u16 = 1;
const DNS_TYPE_AAAA: u16 = 28;
const MAX_DISCOVERED_TARGETS: usize = 8;
const TUNNEL_SETTLE_DELAY: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthState {
    Healthy,
    Degraded,
    Recovering,
    AuthenticationRequired,
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FailureCategory {
    Dns,
    Route,
    Connection,
    Tls,
    Timeout,
    Http,
}

impl FailureCategory {
    fn label(self) -> &'static str {
        match self {
            Self::Dns => "DNS",
            Self::Route => "route",
            Self::Connection => "tunnel connectivity",
            Self::Tls => "TLS",
            Self::Timeout => "timeout",
            Self::Http => "HTTP protocol",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct CheckFailure {
    category: FailureCategory,
    target: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TargetCheckResult {
    Passed,
    NoTarget,
}

#[derive(Default)]
struct HealthTargetPool {
    selected: Option<Url>,
}

impl CheckFailure {
    fn new(category: FailureCategory, target: &Url) -> Self {
        Self {
            category,
            target: sanitized_url(target),
        }
    }
}

#[derive(Clone)]
pub struct HealthPath {
    pub socks5_listen: Option<String>,
    pub socks5_username: String,
    pub socks5_password: String,
}

impl HealthPath {
    fn netstack_mode(&self) -> bool {
        self.socks5_listen.is_some()
    }

    fn local_socks_endpoint(&self) -> Result<String> {
        let listen = self
            .socks5_listen
            .as_deref()
            .context("SOCKS5 listen address is missing")?;
        if let Ok(mut address) = listen.parse::<SocketAddr>() {
            if address.ip().is_unspecified() {
                address.set_ip(match address.ip() {
                    IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
                    IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
                });
            }
            return Ok(address.to_string());
        }
        Ok(listen.to_string())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StateDecision {
    None,
    Recover { attempt: u32 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecoveryOutcome {
    Recovered,
    AuthenticationRequired,
    RateLimited,
    Failed,
}

struct HealthStateMachine {
    state: HealthState,
    consecutive_failures: u32,
    recovery_attempts: u32,
    failure_threshold: u32,
    max_recovery_attempts: u32,
    recovery_cooldown: Duration,
    next_recovery_at: Option<Instant>,
}

impl HealthStateMachine {
    fn new(config: &HealthCheckConfig) -> Self {
        Self {
            state: HealthState::Healthy,
            consecutive_failures: 0,
            recovery_attempts: 0,
            failure_threshold: config.failure_threshold,
            max_recovery_attempts: config.max_recovery_attempts,
            recovery_cooldown: Duration::from_secs(config.recovery_cooldown_seconds),
            next_recovery_at: None,
        }
    }

    fn record_success(&mut self) -> bool {
        if self.state == HealthState::AuthenticationRequired {
            return false;
        }
        let changed = self.state != HealthState::Healthy;
        self.state = HealthState::Healthy;
        self.consecutive_failures = 0;
        self.recovery_attempts = 0;
        self.next_recovery_at = None;
        changed
    }

    fn record_failure(&mut self, now: Instant) -> StateDecision {
        if matches!(
            self.state,
            HealthState::Recovering | HealthState::AuthenticationRequired | HealthState::Failed
        ) {
            return StateDecision::None;
        }

        self.consecutive_failures = self
            .consecutive_failures
            .saturating_add(1)
            .min(self.failure_threshold);
        self.state = HealthState::Degraded;
        let cooling_down = self
            .next_recovery_at
            .is_some_and(|next_recovery| now < next_recovery);
        if self.consecutive_failures < self.failure_threshold || cooling_down {
            return StateDecision::None;
        }

        if self.recovery_attempts >= self.max_recovery_attempts {
            self.state = HealthState::Failed;
            return StateDecision::None;
        }

        self.recovery_attempts += 1;
        self.state = HealthState::Recovering;
        StateDecision::Recover {
            attempt: self.recovery_attempts,
        }
    }

    fn finish_recovery(&mut self, outcome: RecoveryOutcome, now: Instant) -> Option<Duration> {
        match outcome {
            RecoveryOutcome::Recovered => {
                self.record_success();
                None
            }
            RecoveryOutcome::AuthenticationRequired => {
                self.state = HealthState::AuthenticationRequired;
                self.next_recovery_at = None;
                None
            }
            RecoveryOutcome::RateLimited | RecoveryOutcome::Failed => {
                if self.recovery_attempts >= self.max_recovery_attempts {
                    self.state = HealthState::Failed;
                    self.next_recovery_at = None;
                    return None;
                }
                let exponent = self.recovery_attempts.saturating_sub(1).min(31);
                let multiplier = 1_u32 << exponent;
                let delay = self
                    .recovery_cooldown
                    .checked_mul(multiplier)
                    .unwrap_or(Duration::MAX);
                self.state = HealthState::Degraded;
                self.next_recovery_at = now.checked_add(delay);
                Some(delay)
            }
        }
    }
}

pub async fn run(
    config: HealthCheckConfig,
    client: &mut Client,
    wg_conf: &mut WgConf,
    tunnel: &TunnelRuntime,
    path: &HealthPath,
) {
    tokio::time::sleep(Duration::from_secs(config.initial_delay_seconds)).await;
    let mut machine = HealthStateMachine::new(&config);
    let mut targets = HealthTargetPool::default();
    let mut warned_no_target = false;

    loop {
        match check_health_targets(&config, wg_conf, path, &mut targets).await {
            Ok(TargetCheckResult::Passed) => {
                warned_no_target = false;
                if machine.record_success() {
                    log::info!("health check passed; tunnel is healthy again");
                } else {
                    log::debug!("health check passed");
                }
            }
            Ok(TargetCheckResult::NoTarget) => {
                if !warned_no_target {
                    log::warn!(
                        "no usable health-check hostname was provided by the VPN server; automatic recovery is idle"
                    );
                    warned_no_target = true;
                }
            }
            Err(failure) => {
                log::warn!(
                    "{} health check failed for {}",
                    failure.category.label(),
                    failure.target
                );
                let decision = machine.record_failure(Instant::now());
                if matches!(
                    machine.state,
                    HealthState::Degraded | HealthState::Recovering
                ) {
                    log::warn!(
                        "health check failed {}/{}",
                        machine.consecutive_failures,
                        machine.failure_threshold
                    );
                }
                if let StateDecision::Recover { attempt } = decision {
                    log::warn!(
                        "starting recovery attempt {}/{}",
                        attempt,
                        machine.max_recovery_attempts
                    );
                    let outcome =
                        recover(&config, client, wg_conf, tunnel, path, &mut targets).await;
                    let delay = machine.finish_recovery(outcome, Instant::now());
                    match machine.state {
                        HealthState::Healthy => log::info!("tunnel recovered successfully"),
                        HealthState::AuthenticationRequired => log::error!(
                            "authentication required; automatic recovery stopped; rerun QR login or complete mobile confirmation"
                        ),
                        HealthState::Failed => log::error!(
                            "maximum recovery attempts reached; automatic recovery stopped; inspect VPN DNS, AllowedIPs, and tunnel connectivity"
                        ),
                        HealthState::Degraded => {
                            if let Some(delay) = delay {
                                if outcome == RecoveryOutcome::RateLimited {
                                    log::warn!(
                                        "recovery rate-limited; retrying in {} seconds",
                                        delay.as_secs()
                                    );
                                } else {
                                    log::warn!(
                                        "recovery failed; retrying in {} seconds",
                                        delay.as_secs()
                                    );
                                }
                            }
                        }
                        HealthState::Recovering => unreachable!(),
                    }
                }
            }
        }

        tokio::time::sleep(Duration::from_secs(config.interval_seconds)).await;
    }
}

async fn recover(
    config: &HealthCheckConfig,
    client: &mut Client,
    wg_conf: &mut WgConf,
    tunnel: &TunnelRuntime,
    path: &HealthPath,
    targets: &mut HealthTargetPool,
) -> RecoveryOutcome {
    if tunnel.recover_current(wg_conf).await.is_err() {
        log::warn!("failed to refresh the current tunnel state");
        return RecoveryOutcome::Failed;
    }
    tokio::time::sleep(TUNNEL_SETTLE_DELAY).await;
    if matches!(
        check_health_targets(config, wg_conf, path, targets).await,
        Ok(TargetCheckResult::Passed)
    ) {
        return RecoveryOutcome::Recovered;
    }

    let refreshed = match client.connect_vpn_for_recovery().await {
        Ok(refreshed) => refreshed,
        Err(error)
            if error
                .downcast_ref::<RecoveryAuthenticationRequired>()
                .is_some() =>
        {
            return RecoveryOutcome::AuthenticationRequired;
        }
        Err(error) if error.downcast_ref::<RecoveryRateLimited>().is_some() => {
            return RecoveryOutcome::RateLimited;
        }
        Err(_) => {
            log::warn!("failed to refresh VPN configuration with the existing session");
            return RecoveryOutcome::Failed;
        }
    };

    if tunnel.apply_refreshed(wg_conf, &refreshed).await.is_err() {
        log::warn!("failed to apply refreshed VPN configuration");
        return RecoveryOutcome::Failed;
    }
    *wg_conf = refreshed;
    tokio::time::sleep(TUNNEL_SETTLE_DELAY).await;
    if matches!(
        check_health_targets(config, wg_conf, path, targets).await,
        Ok(TargetCheckResult::Passed)
    ) {
        RecoveryOutcome::Recovered
    } else {
        RecoveryOutcome::Failed
    }
}

async fn check_health_targets(
    config: &HealthCheckConfig,
    wg_conf: &WgConf,
    path: &HealthPath,
    targets: &mut HealthTargetPool,
) -> std::result::Result<TargetCheckResult, CheckFailure> {
    let discovered = discovered_targets(
        wg_conf
            .dns_domains
            .iter()
            .chain(wg_conf.dns_policy.exact_v4.keys())
            .chain(wg_conf.dns_policy.exact_v6.keys())
            .chain(wg_conf.dns_policy.wildcard_v4.keys())
            .chain(wg_conf.dns_policy.suffix_v4.keys()),
    );
    let mut first_failure = None;
    let selected = targets
        .selected
        .clone()
        .filter(|selected| discovered.contains(selected));
    if selected.is_none() {
        targets.selected = None;
    }

    if let Some(selected) = selected.as_ref() {
        match check_target(config, wg_conf, path, selected).await {
            Ok(()) => return Ok(TargetCheckResult::Passed),
            Err(failure) => first_failure = Some(failure),
        }
    }

    for target in discovered.iter().filter(|candidate| {
        selected
            .as_ref()
            .is_none_or(|selected| selected != *candidate)
    }) {
        match check_target(config, wg_conf, path, target).await {
            Ok(()) => {
                if targets.selected.as_ref() != Some(target) {
                    log::info!("selected a server-provided health-check target");
                }
                targets.selected = Some(target.clone());
                return Ok(TargetCheckResult::Passed);
            }
            Err(failure) => {
                if first_failure.is_none() {
                    first_failure = Some(failure);
                }
            }
        }
    }

    // Preserve explicitly configured targets as a compatibility fallback. All
    // configured targets must pass, matching the legacy health-check behavior.
    for configured in &config.targets {
        let target = Url::parse(&configured.url)
            .map_err(|_| CheckFailure::new(FailureCategory::Http, &fallback_url()))?;
        check_target(config, wg_conf, path, &target).await?;
    }
    if !config.targets.is_empty() {
        return Ok(TargetCheckResult::Passed);
    }

    match (selected, first_failure) {
        (Some(_), Some(failure)) => Err(failure),
        _ => Ok(TargetCheckResult::NoTarget),
    }
}

fn discovered_targets<'a>(domains: impl IntoIterator<Item = &'a String>) -> Vec<Url> {
    let mut seen = HashSet::new();
    domains
        .into_iter()
        .filter_map(|domain| discovered_target(domain))
        .filter(|target| seen.insert(target.clone()))
        .take(MAX_DISCOVERED_TARGETS)
        .collect()
}

fn discovered_target(domain: &str) -> Option<Url> {
    let domain = domain.trim().trim_end_matches('.');
    let domain = domain
        .strip_prefix("*.")
        .or_else(|| domain.strip_prefix('.'))
        .unwrap_or(domain);
    if domain.is_empty()
        || domain.starts_with('.')
        || domain.contains(['*', '/', ':', '?', '#', '@', '[', ']'])
    {
        return None;
    }
    let target = Url::parse(&format!("https://{domain}/")).ok()?;
    if !target.username().is_empty()
        || target.password().is_some()
        || target.host_str()?.parse::<IpAddr>().is_ok()
    {
        return None;
    }
    Some(target)
}

async fn check_target(
    config: &HealthCheckConfig,
    wg_conf: &WgConf,
    path: &HealthPath,
    target: &Url,
) -> std::result::Result<(), CheckFailure> {
    let host = target
        .host_str()
        .ok_or_else(|| CheckFailure::new(FailureCategory::Dns, target))?;
    let mut addresses = match resolve_through_vpn_dns(config, wg_conf, path, host).await {
        Ok(addresses) => addresses,
        Err(FailureCategory::Dns) => {
            // One immediate DNS retry filters out a transient resolver failure.
            resolve_through_vpn_dns(config, wg_conf, path, host)
                .await
                .map_err(|category| CheckFailure::new(category, target))?
        }
        Err(category) => return Err(CheckFailure::new(category, target)),
    };
    addresses.sort();
    addresses.dedup();
    if addresses.is_empty() {
        return Err(CheckFailure::new(FailureCategory::Dns, target));
    }
    if addresses
        .iter()
        .any(|address| !address_is_tunneled(*address, &wg_conf.allowed_ips))
    {
        return Err(CheckFailure::new(FailureCategory::Route, target));
    }

    check_http(
        target,
        &addresses,
        path,
        Duration::from_secs(config.request_timeout_seconds),
    )
    .await
    .map_err(|category| CheckFailure::new(category, target))
}

async fn resolve_through_vpn_dns(
    config: &HealthCheckConfig,
    wg_conf: &WgConf,
    path: &HealthPath,
    host: &str,
) -> std::result::Result<Vec<IpAddr>, FailureCategory> {
    if let Ok(address) = host.parse::<IpAddr>() {
        return Ok(vec![address]);
    }

    if let Some(mut addresses) = wg_conf.dns_policy.dynamic_addresses(host) {
        if wg_conf.address6.is_empty() {
            addresses.retain(IpAddr::is_ipv4);
        }
        return (!addresses.is_empty())
            .then_some(addresses)
            .ok_or(FailureCategory::Dns);
    }

    let split_domain = wg_conf.dns_policy.matches_split_domain(host);
    let configured_servers = if split_domain {
        wg_conf.dns_policy.split_dns_servers.join(",")
    } else {
        wg_conf.dns.clone()
    };
    let dns_servers = configured_servers
        .split(',')
        .filter_map(|value| value.trim().parse::<IpAddr>().ok())
        .collect::<Vec<_>>();
    if dns_servers.is_empty() {
        return Err(FailureCategory::Dns);
    }
    if dns_servers
        .iter()
        .any(|server| !address_is_tunneled(*server, &wg_conf.allowed_ips))
    {
        return Err(FailureCategory::Route);
    }

    let timeout = Duration::from_secs(config.dns_timeout_seconds);
    let deadline = Instant::now() + timeout;
    let mut addresses = Vec::new();
    for server in dns_servers {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break;
        }
        if let Ok(mut found) = query_dns(path, server, host, DNS_TYPE_A, remaining).await {
            addresses.append(&mut found);
        }
        if !wg_conf.address6.is_empty() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if !remaining.is_zero() {
                if let Ok(mut found) = query_dns(path, server, host, DNS_TYPE_AAAA, remaining).await
                {
                    addresses.append(&mut found);
                }
            }
        }
        if !addresses.is_empty() {
            break;
        }
    }
    if addresses.is_empty() {
        Err(FailureCategory::Dns)
    } else {
        Ok(addresses)
    }
}

async fn query_dns(
    path: &HealthPath,
    server: IpAddr,
    host: &str,
    query_type: u16,
    timeout: Duration,
) -> io::Result<Vec<IpAddr>> {
    tokio::time::timeout(timeout, async {
        let server = SocketAddr::new(server, 53);
        let mut stream = if path.netstack_mode() {
            socks_connect(path, server).await?
        } else {
            TcpStream::connect(server).await?
        };
        let id = rand::thread_rng().gen::<u16>();
        let packet = build_dns_query(host, query_type, id)?;
        let packet_len = u16::try_from(packet.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DNS query too large"))?;
        stream.write_all(&packet_len.to_be_bytes()).await?;
        stream.write_all(&packet).await?;

        let mut response_len = [0_u8; 2];
        stream.read_exact(&mut response_len).await?;
        let response_len = u16::from_be_bytes(response_len) as usize;
        let mut response = vec![0_u8; response_len];
        stream.read_exact(&mut response).await?;
        parse_dns_response(&response, id)
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS query timed out"))?
}

fn build_dns_query(host: &str, query_type: u16, id: u16) -> io::Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100_u16.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    for label in host.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid DNS name",
            ));
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&query_type.to_be_bytes());
    packet.extend_from_slice(&1_u16.to_be_bytes());
    Ok(packet)
}

fn parse_dns_response(response: &[u8], expected_id: u16) -> io::Result<Vec<IpAddr>> {
    if response.len() < 12 || read_u16(response, 0)? != expected_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid DNS response",
        ));
    }
    let flags = read_u16(response, 2)?;
    if flags & 0x8000 == 0 || flags & 0x000f != 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "DNS server returned an error",
        ));
    }
    let questions = read_u16(response, 4)? as usize;
    let answers = read_u16(response, 6)? as usize;
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_dns_name(response, offset)?;
        offset = offset
            .checked_add(4)
            .filter(|offset| *offset <= response.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated DNS question"))?;
    }

    let mut addresses = Vec::new();
    for _ in 0..answers {
        offset = skip_dns_name(response, offset)?;
        let record_type = read_u16(response, offset)?;
        let class = read_u16(response, offset + 2)?;
        let data_len = read_u16(response, offset + 8)? as usize;
        offset += 10;
        let end = offset
            .checked_add(data_len)
            .filter(|end| *end <= response.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated DNS answer"))?;
        if class == 1 && record_type == DNS_TYPE_A && data_len == 4 {
            addresses.push(IpAddr::from([
                response[offset],
                response[offset + 1],
                response[offset + 2],
                response[offset + 3],
            ]));
        } else if class == 1 && record_type == DNS_TYPE_AAAA && data_len == 16 {
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&response[offset..end]);
            addresses.push(IpAddr::from(octets));
        }
        offset = end;
    }
    Ok(addresses)
}

fn read_u16(data: &[u8], offset: usize) -> io::Result<u16> {
    let bytes = data
        .get(offset..offset + 2)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated DNS response"))?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn skip_dns_name(data: &[u8], mut offset: usize) -> io::Result<usize> {
    loop {
        let length = *data
            .get(offset)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated DNS name"))?;
        if length & 0xc0 == 0xc0 {
            return offset
                .checked_add(2)
                .filter(|offset| *offset <= data.len())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "truncated DNS pointer")
                });
        }
        offset += 1;
        if length == 0 {
            return Ok(offset);
        }
        if length & 0xc0 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid DNS label",
            ));
        }
        offset = offset
            .checked_add(length as usize)
            .filter(|offset| *offset <= data.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated DNS label"))?;
    }
}

async fn socks_connect(path: &HealthPath, target: SocketAddr) -> io::Result<TcpStream> {
    let endpoint = path
        .local_socks_endpoint()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid SOCKS5 endpoint"))?;
    let mut stream = TcpStream::connect(endpoint).await?;
    let use_auth = !path.socks5_username.is_empty();
    let method = if use_auth { 0x02 } else { 0x00 };
    stream.write_all(&[0x05, 0x01, method]).await?;
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting != [0x05, method] {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 authentication method rejected",
        ));
    }
    if use_auth {
        let username = path.socks5_username.as_bytes();
        let password = path.socks5_password.as_bytes();
        if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS5 credentials are too long",
            ));
        }
        let mut auth = Vec::with_capacity(username.len() + password.len() + 3);
        auth.extend_from_slice(&[0x01, username.len() as u8]);
        auth.extend_from_slice(username);
        auth.push(password.len() as u8);
        auth.extend_from_slice(password);
        stream.write_all(&auth).await?;
        let mut reply = [0_u8; 2];
        stream.read_exact(&mut reply).await?;
        if reply != [0x01, 0x00] {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 authentication failed",
            ));
        }
    }

    let mut request = vec![0x05, 0x01, 0x00];
    match target.ip() {
        IpAddr::V4(ip) => {
            request.push(0x01);
            request.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            request.push(0x04);
            request.extend_from_slice(&ip.octets());
        }
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;

    let mut reply = [0_u8; 4];
    stream.read_exact(&mut reply).await?;
    if reply[0] != 0x05 || reply[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            "SOCKS5 connect failed",
        ));
    }
    let address_len = match reply[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length).await?;
            length[0] as usize
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid SOCKS5 response",
            ));
        }
    };
    let mut ignored = vec![0_u8; address_len + 2];
    stream.read_exact(&mut ignored).await?;
    Ok(stream)
}

async fn check_http(
    target: &Url,
    addresses: &[IpAddr],
    path: &HealthPath,
    timeout: Duration,
) -> std::result::Result<(), FailureCategory> {
    let host = target.host_str().ok_or(FailureCategory::Http)?;
    let port = target
        .port_or_known_default()
        .ok_or(FailureCategory::Http)?;
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .connect_timeout(timeout)
        .timeout(timeout);

    if path.netstack_mode() {
        let endpoint = path
            .local_socks_endpoint()
            .map_err(|_| FailureCategory::Connection)?;
        let proxy_url = format!("socks5h://{endpoint}");
        let mut proxy = reqwest::Proxy::all(&proxy_url).map_err(|_| FailureCategory::Connection)?;
        if !path.socks5_username.is_empty() {
            proxy = proxy.basic_auth(&path.socks5_username, &path.socks5_password);
        }
        builder = builder.proxy(proxy);
    } else {
        let socket_addresses = addresses
            .iter()
            .copied()
            .map(|address| SocketAddr::new(address, port))
            .collect::<Vec<_>>();
        builder = builder.resolve_to_addrs(host, &socket_addresses);
    }

    let client = builder.build().map_err(|_| FailureCategory::Http)?;
    match client.get(target.clone()).send().await {
        Ok(_) => Ok(()),
        Err(error) => Err(classify_request_error(&error)),
    }
}

fn classify_request_error(error: &reqwest::Error) -> FailureCategory {
    if error.is_timeout() {
        return FailureCategory::Timeout;
    }
    // Error details are inspected only for classification and are never logged;
    // reqwest errors can contain the original URL including a private query.
    let detail = format!("{error:#}").to_ascii_lowercase();
    if detail.contains("dns") || detail.contains("resolve") || detail.contains("no such host") {
        FailureCategory::Dns
    } else if detail.contains("tls")
        || detail.contains("ssl")
        || detail.contains("certificate")
        || detail.contains("handshake")
        || detail.contains("record overflow")
        || detail.contains("wrong version number")
    {
        FailureCategory::Tls
    } else if error.is_connect() {
        FailureCategory::Connection
    } else {
        FailureCategory::Http
    }
}

fn address_is_tunneled(address: IpAddr, allowed_ips: &[String]) -> bool {
    let host_route = match address {
        IpAddr::V4(_) => format!("{address}/32"),
        IpAddr::V6(_) => format!("{address}/128"),
    };
    allowed_ips.iter().any(|route| {
        let normalized;
        let route = if route.contains('/') {
            route.as_str()
        } else {
            normalized = if route.contains(':') {
                format!("{route}/128")
            } else {
                format!("{route}/32")
            };
            &normalized
        };
        crate::utils::intersect_cidr_with_cidr(route, &host_route).is_some()
    })
}

fn sanitized_url(url: &Url) -> String {
    let mut sanitized = url.clone();
    sanitized.set_query(None);
    sanitized.set_fragment(None);
    sanitized.to_string()
}

fn fallback_url() -> Url {
    Url::parse("https://internal.example.com/").expect("static health URL is valid")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{HealthCheckTarget, NetstackDnsPolicy};
    use tokio::net::TcpListener;

    fn config() -> HealthCheckConfig {
        HealthCheckConfig {
            enabled: true,
            targets: vec![HealthCheckTarget {
                url: "https://internal.example.com/".to_string(),
            }],
            interval_seconds: 60,
            initial_delay_seconds: 0,
            dns_timeout_seconds: 1,
            request_timeout_seconds: 1,
            failure_threshold: 3,
            recovery_cooldown_seconds: 60,
            max_recovery_attempts: 3,
        }
    }

    fn direct_path() -> HealthPath {
        HealthPath {
            socks5_listen: None,
            socks5_username: String::new(),
            socks5_password: String::new(),
        }
    }

    async fn response_server(status: u16) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await;
            let response = format!("HTTP/1.1 {status} test\r\nContent-Length: 0\r\n\r\n");
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        (address, task)
    }

    #[test]
    fn single_failure_does_not_start_recovery() {
        let mut machine = HealthStateMachine::new(&config());
        assert_eq!(machine.record_failure(Instant::now()), StateDecision::None);
        assert_eq!(machine.state, HealthState::Degraded);
        assert_eq!(machine.recovery_attempts, 0);
    }

    #[test]
    fn threshold_starts_only_one_recovery() {
        let mut machine = HealthStateMachine::new(&config());
        let now = Instant::now();
        assert_eq!(machine.record_failure(now), StateDecision::None);
        assert_eq!(machine.record_failure(now), StateDecision::None);
        assert_eq!(
            machine.record_failure(now),
            StateDecision::Recover { attempt: 1 }
        );
        assert_eq!(machine.record_failure(now), StateDecision::None);
        assert_eq!(machine.recovery_attempts, 1);
    }

    #[test]
    fn successful_recovery_resets_failures() {
        let mut machine = HealthStateMachine::new(&config());
        let now = Instant::now();
        for _ in 0..3 {
            machine.record_failure(now);
        }
        machine.finish_recovery(RecoveryOutcome::Recovered, now);

        assert_eq!(machine.state, HealthState::Healthy);
        assert_eq!(machine.consecutive_failures, 0);
        assert_eq!(machine.recovery_attempts, 0);
    }

    #[test]
    fn failed_recovery_honors_cooldown_and_backoff() {
        let mut machine = HealthStateMachine::new(&config());
        let now = Instant::now();
        for _ in 0..3 {
            machine.record_failure(now);
        }
        assert_eq!(
            machine.finish_recovery(RecoveryOutcome::Failed, now),
            Some(Duration::from_secs(60))
        );
        assert_eq!(
            machine.record_failure(now + Duration::from_secs(59)),
            StateDecision::None
        );
        assert_eq!(machine.consecutive_failures, machine.failure_threshold);
        assert_eq!(
            machine.record_failure(now + Duration::from_secs(60)),
            StateDecision::Recover { attempt: 2 }
        );
        assert_eq!(
            machine.finish_recovery(RecoveryOutcome::RateLimited, now + Duration::from_secs(60)),
            Some(Duration::from_secs(120))
        );
    }

    #[test]
    fn authentication_required_never_retries() {
        let mut machine = HealthStateMachine::new(&config());
        let now = Instant::now();
        for _ in 0..3 {
            machine.record_failure(now);
        }
        machine.finish_recovery(RecoveryOutcome::AuthenticationRequired, now);
        for offset in [60, 120, 3600] {
            assert_eq!(
                machine.record_failure(now + Duration::from_secs(offset)),
                StateDecision::None
            );
        }
        assert_eq!(machine.state, HealthState::AuthenticationRequired);
        assert_eq!(machine.recovery_attempts, 1);
    }

    #[test]
    fn maximum_recovery_attempts_enter_failed_state() {
        let mut machine = HealthStateMachine::new(&config());
        let mut now = Instant::now();
        for expected_attempt in 1..=3 {
            while machine.state != HealthState::Recovering {
                machine.record_failure(now);
            }
            assert_eq!(machine.recovery_attempts, expected_attempt);
            machine.finish_recovery(RecoveryOutcome::Failed, now);
            if expected_attempt < 3 {
                now = machine.next_recovery_at.unwrap();
            }
        }

        assert_eq!(machine.state, HealthState::Failed);
        assert_eq!(machine.record_failure(now), StateDecision::None);
    }

    #[tokio::test]
    async fn http_401_and_403_are_network_reachable() {
        for status in [401, 403] {
            let (address, server) = response_server(status).await;
            let target = Url::parse(&format!("http://{address}/private")).unwrap();
            assert_eq!(
                check_http(
                    &target,
                    &[address.ip()],
                    &direct_path(),
                    Duration::from_secs(1)
                )
                .await,
                Ok(())
            );
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn dns_tcp_tls_and_http_failures_are_classified() {
        let mut wg_conf = test_wg_conf();
        wg_conf.dns.clear();
        assert_eq!(
            resolve_through_vpn_dns(&config(), &wg_conf, &direct_path(), "internal.example.com")
                .await,
            Err(FailureCategory::Dns)
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unused = listener.local_addr().unwrap();
        drop(listener);
        let target = Url::parse(&format!("http://{unused}/")).unwrap();
        assert_eq!(
            check_http(
                &target,
                &[unused.ip()],
                &direct_path(),
                Duration::from_secs(1)
            )
            .await,
            Err(FailureCategory::Connection)
        );

        let (plain_tls, tls_server) = response_server(200).await;
        let target = Url::parse(&format!("https://{plain_tls}/")).unwrap();
        assert_eq!(
            check_http(
                &target,
                &[plain_tls.ip()],
                &direct_path(),
                Duration::from_secs(1)
            )
            .await,
            Err(FailureCategory::Tls)
        );
        tls_server.await.unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let invalid_server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request).await;
            stream.write_all(b"not-http\r\n\r\n").await.unwrap();
        });
        let target = Url::parse(&format!("http://{address}/")).unwrap();
        assert_eq!(
            check_http(
                &target,
                &[address.ip()],
                &direct_path(),
                Duration::from_secs(1)
            )
            .await,
            Err(FailureCategory::Http)
        );
        invalid_server.await.unwrap();
    }

    #[tokio::test]
    async fn cancelling_health_request_closes_the_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let target = Url::parse(&format!("http://{address}/hang")).unwrap();
        let task = tokio::spawn(async move {
            check_http(
                &target,
                &[address.ip()],
                &direct_path(),
                Duration::from_secs(60),
            )
            .await
        });
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 1024];
        let _ = stream.read(&mut request).await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let closed = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut request))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(closed, 0);
    }

    #[test]
    fn logged_target_never_contains_query_fragment_or_credentials() {
        let target = Url::parse(
            "https://internal.example.com/private?token=secret-token&otp=123456#password",
        )
        .unwrap();
        let logged = sanitized_url(&target);

        assert_eq!(logged, "https://internal.example.com/private");
        for secret in ["secret-token", "123456", "password", "token", "otp"] {
            assert!(!logged.contains(secret));
        }
    }

    #[test]
    fn route_check_requires_allowed_ip_membership() {
        let routes = vec![
            "10.0.0.0/8".to_string(),
            "2001:db8::/32".to_string(),
            "192.0.2.1".to_string(),
        ];
        assert!(address_is_tunneled("10.2.3.4".parse().unwrap(), &routes));
        assert!(address_is_tunneled("2001:db8::1".parse().unwrap(), &routes));
        assert!(address_is_tunneled("192.0.2.1".parse().unwrap(), &routes));
        assert!(!address_is_tunneled("192.0.2.2".parse().unwrap(), &routes));
    }

    #[test]
    fn server_domains_become_bounded_deduplicated_https_targets() {
        let mut domains = vec![
            "INTERNAL.EXAMPLE.COM.".to_string(),
            "internal.example.com".to_string(),
            "*.example.com".to_string(),
            ".example.com".to_string(),
            "https://internal.example.com/".to_string(),
            "192.0.2.1".to_string(),
        ];
        domains.extend((0..10).map(|index| format!("host{index}.example.com")));

        let targets = discovered_targets(&domains);

        assert_eq!(targets.len(), MAX_DISCOVERED_TARGETS);
        assert_eq!(targets[0].as_str(), "https://internal.example.com/");
        assert!(targets
            .iter()
            .any(|target| target.as_str() == "https://example.com/"));
        assert!(targets.iter().all(|target| !target.as_str().contains('*')));
    }

    #[tokio::test]
    async fn missing_server_and_configured_targets_stays_idle() {
        let mut config = config();
        config.targets.clear();
        let mut targets = HealthTargetPool::default();

        assert_eq!(
            check_health_targets(&config, &test_wg_conf(), &direct_path(), &mut targets).await,
            Ok(TargetCheckResult::NoTarget)
        );
    }

    #[tokio::test]
    async fn health_dns_never_falls_back_to_the_system_resolver() {
        let mut wg_conf = test_wg_conf();
        wg_conf.dns.clear();

        assert_eq!(
            resolve_through_vpn_dns(&config(), &wg_conf, &direct_path(), "localhost").await,
            Err(FailureCategory::Dns)
        );
    }

    #[tokio::test]
    async fn dynamic_health_dns_records_avoid_upstream_resolvers() {
        let mut wg_conf = test_wg_conf();
        wg_conf.dns = "8.8.8.8".to_string();
        wg_conf.dns_policy.exact_v4.insert(
            "internal.example.com".to_string(),
            vec!["10.0.0.10/32".to_string()],
        );

        assert_eq!(
            resolve_through_vpn_dns(&config(), &wg_conf, &direct_path(), "internal.example.com")
                .await,
            Ok(vec!["10.0.0.10".parse().unwrap()])
        );
    }

    #[tokio::test]
    async fn split_health_dns_does_not_fall_back_to_public_resolvers() {
        let mut wg_conf = test_wg_conf();
        wg_conf.dns = "8.8.8.8".to_string();
        wg_conf.dns_policy.split_domains = vec!["internal.example.com".to_string()];
        wg_conf.dns_policy.split_dns_servers.clear();

        assert_eq!(
            resolve_through_vpn_dns(&config(), &wg_conf, &direct_path(), "internal.example.com")
                .await,
            Err(FailureCategory::Dns)
        );
    }

    #[tokio::test]
    async fn discovery_failures_do_not_recover_until_a_target_was_selected() {
        let mut config = config();
        config.targets.clear();
        let mut wg_conf = test_wg_conf();
        wg_conf.dns.clear();
        wg_conf.dns_domains = vec!["localhost".to_string()];
        let target = Url::parse("https://localhost/").unwrap();
        let mut targets = HealthTargetPool::default();

        assert_eq!(
            check_health_targets(&config, &wg_conf, &direct_path(), &mut targets).await,
            Ok(TargetCheckResult::NoTarget)
        );

        targets.selected = Some(target.clone());
        assert_eq!(
            check_health_targets(&config, &wg_conf, &direct_path(), &mut targets).await,
            Err(CheckFailure::new(FailureCategory::Dns, &target))
        );
    }

    fn test_wg_conf() -> WgConf {
        WgConf {
            address: "10.0.0.2/32".to_string(),
            address6: String::new(),
            peer_address: "192.0.2.1:51820".to_string(),
            mtu: 1280,
            public_key: String::new(),
            private_key: String::new(),
            peer_key: String::new(),
            allowed_ips: vec!["10.0.0.0/8".to_string()],
            routes: vec!["10.0.0.0/8".to_string()],
            dns: "10.0.0.53".to_string(),
            dns_domains: Vec::new(),
            dns_policy: NetstackDnsPolicy::default(),
            protocol: 0,
        }
    }
}
