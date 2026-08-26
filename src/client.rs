use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use std::{fs, io};

use anyhow::{anyhow, bail, Context, Result};
use cookie_store::CookieStore;
use futures::stream::{FuturesUnordered, StreamExt};
use futures::SinkExt;
use reqwest::cookie::CookieStore as ReqwestCookieStore;
use reqwest::header;
use reqwest::{ClientBuilder, Response, Url};
use reqwest_cookie_store::CookieStoreMutex;
use serde::de::DeserializeOwned;
use serde_json::{json, Map, Value};
use sha2::Digest;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::broadcast;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::{
    header as websocket_header, HeaderValue as WebSocketHeaderValue, Request as WebSocketRequest,
};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async, WebSocketStream};

use crate::api::{corplink_user_agent, ApiName, ApiUrl, URL_GET_COMPANY};
use crate::config::{
    normalize_dns_name, Config, NetstackDnsPolicy, RouteMode, WgConf, PLATFORM_CORPLINK,
    PLATFORM_CORPLINK_EMAIL, PLATFORM_CORPLINK_QR, PLATFORM_CORPLINK_V1, PLATFORM_LARK,
    PLATFORM_LDAP, PLATFORM_OIDC, STRATEGY_DEFAULT, STRATEGY_LATENCY,
};
use crate::qrcode::TerminalQrCode;
use crate::resp::*;
use crate::state::State;
use crate::totp::{totp_offset, TIME_STEP};
use crate::utils;

const COOKIE_FILE_SUFFIX: &str = "cookies.json";
const SIGN_ROOT_KEY_VERSION: u64 = 1;
const SIGN_SECRET: &[u8] = b"TOK@@AoNfRIX+3bla%";
const SIGN_HASH_BLOCK_SIZE: usize = 64;
const SIGN_HASH_OUTPUT_SIZE: usize = 32;
const VPN_MFA_REQUIRED_CODE: i32 = 3002;
const VPN_SESSION_MISSING_CODE: i32 = 10220001;
const VPN_MFA_SCENE: &str = "vpn";
const VPN_PUSH_CONFIRM_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct RecoveryAuthenticationRequired;

impl fmt::Display for RecoveryAuthenticationRequired {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "authentication required for VPN recovery")
    }
}

impl std::error::Error for RecoveryAuthenticationRequired {}

#[derive(Debug)]
pub struct RecoveryRateLimited;

impl fmt::Display for RecoveryRateLimited {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VPN recovery request was rate-limited")
    }
}

impl std::error::Error for RecoveryRateLimited {}

#[derive(Clone, Debug, PartialEq)]
struct WebSocketEvent {
    event_id: String,
    action: String,
    data: Option<Value>,
}

fn parse_websocket_event(text: &str) -> Option<WebSocketEvent> {
    let envelope: Value = serde_json::from_str(text).ok()?;
    let data = envelope.get("data").and_then(|data| match data {
        Value::String(encoded) => serde_json::from_str::<Value>(encoded).ok(),
        Value::Object(_) => Some(data.clone()),
        _ => None,
    });
    Some(WebSocketEvent {
        event_id: envelope.get("id")?.as_str()?.to_string(),
        action: envelope.get("action")?.as_str()?.to_string(),
        data,
    })
}

fn vpn_push_result(event: &WebSocketEvent, expected_message_id: &str) -> Option<bool> {
    if event.action != "push_mfa" {
        return None;
    }
    let payload = event.data.as_ref()?;
    if payload.get("message_id")?.as_str()? != expected_message_id {
        return None;
    }
    match payload.get("check_result")?.as_str()? {
        "confirm" => Some(true),
        "reject" | "cancel" => Some(false),
        _ => None,
    }
}

async fn wait_for_vpn_push_confirmation(
    events: &mut broadcast::Receiver<WebSocketEvent>,
    expected_message_id: &str,
    wait_timeout: Duration,
) -> Result<bool> {
    let deadline = tokio::time::sleep(wait_timeout);
    tokio::pin!(deadline);

    loop {
        tokio::select! {
            _ = &mut deadline => return Ok(false),
            event = events.recv() => {
                let event = event.context("VPN push WebSocket event stream ended")?;
                let Some(confirmed) = vpn_push_result(&event, expected_message_id) else {
                    if event.action == "push_mfa" {
                        log::info!(
                            "received VPN push event for a different or incomplete request"
                        );
                    }
                    continue;
                };
                if confirmed {
                    log::info!("VPN push confirmation approved");
                    return Ok(true);
                }
                bail!("VPN push confirmation was rejected");
            }
        }
    }
}

async fn pump_vpn_push_websocket<S>(
    websocket: &mut WebSocketStream<S>,
    events: &broadcast::Sender<WebSocketEvent>,
    received_ids: &mut HashSet<String>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let heartbeat = tokio::time::sleep(Duration::from_secs(10));
    tokio::pin!(heartbeat);

    loop {
        tokio::select! {
            _ = &mut heartbeat => {
                websocket
                    .send(Message::Ping(Vec::new()))
                    .await
                    .context("failed to send VPN push WebSocket heartbeat")?;
                log::info!("VPN push WebSocket ping sent");
                heartbeat.as_mut().reset(tokio::time::Instant::now() + Duration::from_secs(10));
            }
            message = websocket.next() => {
                match message {
                    Some(Ok(message @ (Message::Text(_) | Message::Binary(_)))) => {
                        log::info!(
                            "received FeiLian WebSocket data frame: type={}, length={}",
                            if matches!(&message, Message::Text(_)) { "text" } else { "binary" },
                            message.len()
                        );
                        let text = match message {
                            Message::Text(text) => text,
                            Message::Binary(bytes) => String::from_utf8(bytes)
                                .context("invalid UTF-8 in FeiLian WebSocket event")?,
                            _ => unreachable!(),
                        };
                        let Some(event) = parse_websocket_event(&text) else {
                            log::info!("received unrecognized FeiLian WebSocket JSON event");
                            continue;
                        };
                        log::info!("received FeiLian WebSocket event: {}", event.action);
                        if event.action == "message_received"
                            || !received_ids.insert(event.event_id.clone())
                        {
                            continue;
                        }
                        let acknowledgement = json!({
                            "id": event.event_id,
                            "action": "message_received",
                            "data": ""
                        });
                        websocket
                            .send(Message::Text(acknowledgement.to_string()))
                            .await
                            .context("failed to acknowledge FeiLian WebSocket event")?;
                        let _ = events.send(event);
                    }
                    Some(Ok(Message::Ping(payload))) => {
                        log::info!("received FeiLian WebSocket ping");
                        websocket
                            .send(Message::Pong(payload))
                            .await
                            .context("failed to reply to VPN push WebSocket ping")?;
                    }
                    Some(Ok(Message::Pong(_))) => {
                        log::info!("received FeiLian WebSocket pong");
                    }
                    Some(Ok(Message::Close(frame))) => {
                        bail!("VPN push WebSocket closed: {frame:?}");
                    }
                    Some(Ok(_)) => {}
                    Some(Err(error)) => bail!("VPN push WebSocket receive failed: {error}"),
                    None => bail!("VPN push WebSocket ended"),
                }
            }
        }
    }
}

async fn maintain_vpn_push_websocket(
    connector: VpnPushConnector,
    mut websocket: VpnPushWebSocket,
    events: broadcast::Sender<WebSocketEvent>,
) {
    let mut received_ids = HashSet::new();
    loop {
        if let Err(error) =
            pump_vpn_push_websocket(&mut websocket, &events, &mut received_ids).await
        {
            log::warn!("VPN push WebSocket disconnected: {error}");
        }

        let mut retry_delay = Duration::from_secs(1);
        loop {
            tokio::time::sleep(retry_delay).await;
            match connector.connect().await {
                Ok(reconnected) => {
                    websocket = reconnected;
                    break;
                }
                Err(error) => {
                    log::warn!("failed to reconnect VPN push WebSocket: {error}");
                    retry_delay = (retry_delay * 2).min(Duration::from_secs(30));
                }
            }
        }
    }
}

fn value_after_keyword(output: &str, keyword: &str) -> Option<String> {
    output.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        while let Some(field) = fields.next() {
            if field.trim_end_matches(':') == keyword {
                return fields.next().map(str::to_string);
            }
        }
        None
    })
}

fn normalize_mac_address(value: &str) -> Option<String> {
    let normalized = value.trim().replace('-', ":").to_ascii_lowercase();
    let valid = normalized
        .split(':')
        .collect::<Vec<_>>()
        .as_slice()
        .iter()
        .all(|part| part.len() == 2 && part.chars().all(|ch| ch.is_ascii_hexdigit()));
    (valid && normalized.split(':').count() == 6).then_some(normalized)
}

#[cfg(target_os = "macos")]
async fn default_interface_mac() -> Option<String> {
    let route = tokio::process::Command::new("/sbin/route")
        .args(["-n", "get", "default"])
        .output()
        .await
        .ok()?;
    let interface = value_after_keyword(&String::from_utf8_lossy(&route.stdout), "interface")?;
    let ifconfig = tokio::process::Command::new("/sbin/ifconfig")
        .arg(interface)
        .output()
        .await
        .ok()?;
    let mac = value_after_keyword(&String::from_utf8_lossy(&ifconfig.stdout), "ether")?;
    normalize_mac_address(&mac)
}

#[cfg(target_os = "linux")]
async fn default_interface_mac() -> Option<String> {
    let route = tokio::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .await
        .ok()?;
    let interface = value_after_keyword(&String::from_utf8_lossy(&route.stdout), "dev")?;
    if !interface
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.'))
    {
        return None;
    }
    let mac = tokio::fs::read_to_string(format!("/sys/class/net/{interface}/address"))
        .await
        .ok()?;
    normalize_mac_address(&mac)
}

#[cfg(target_os = "windows")]
async fn default_interface_mac() -> Option<String> {
    let output = tokio::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1 | Get-NetAdapter).MacAddress",
        ])
        .output()
        .await
        .ok()?;
    normalize_mac_address(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
async fn default_interface_mac() -> Option<String> {
    None
}

fn vpn_connect_body(
    public_key: &str,
    otp: &str,
    route_mode: &RouteMode,
    smac: &str,
) -> Map<String, Value> {
    let mut body = Map::new();
    body.insert(
        "mode".to_string(),
        json!(match route_mode {
            RouteMode::Split => "Split",
            RouteMode::Full => "Full",
        }),
    );
    body.insert("not_auto".to_string(), json!(true));
    body.insert("export_id".to_string(), json!(0));
    body.insert("public_key".to_string(), json!(public_key));
    if !otp.is_empty() {
        body.insert("otp".to_string(), json!(otp));
    }
    body.insert("smac".to_string(), json!(smac));
    body
}

fn select_supported_vpn_mfa_type<'a>(
    info: &'a RespVpnMfaType,
    preferred: Option<&str>,
) -> Option<&'a str> {
    let mut offered = info
        .vpn_types
        .iter()
        .chain(info.types.iter())
        .map(String::as_str);
    if let Some(preferred) =
        preferred.filter(|preferred| matches!(*preferred, "push" | "email" | "mobile" | "otp"))
    {
        if let Some(kind) = offered.clone().find(|kind| *kind == preferred) {
            return Some(kind);
        }
    }
    offered.find(|kind| matches!(*kind, "push" | "email" | "mobile" | "otp"))
}

fn merge_additional_routes(
    mut routes: Vec<String>,
    additional_routes: &[String],
    has_ipv6_address: bool,
) -> Vec<String> {
    for route in additional_routes {
        if !crate::utils::is_valid_cidr(route) {
            log::warn!("ignoring invalid vpn_additional_routes CIDR: {:?}", route);
            continue;
        }
        if !has_ipv6_address && route.contains(':') {
            log::info!(
                "ignoring additional IPv6 route {:?} because the server did not assign an IPv6 address",
                route
            );
            continue;
        }
        if !routes.contains(route) {
            routes.push(route.clone());
        }
    }
    routes
}

#[derive(Debug, PartialEq, Eq)]
struct NetstackDnsConfig {
    servers: String,
    split_servers: Vec<String>,
    routes: Vec<String>,
}

fn netstack_dns_config(
    primary: &str,
    backup: &str,
    central_dns: Option<&RespCentralDns>,
    has_ipv6_address: bool,
) -> NetstackDnsConfig {
    let mut servers = Vec::new();
    let mut split_servers = Vec::new();
    let mut routes = Vec::new();
    for configured in [primary, backup] {
        for value in configured.split(',') {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            let Ok(ip) = value.parse::<IpAddr>() else {
                log::warn!("ignoring invalid VPN DNS server: {:?}", value);
                continue;
            };
            if ip.is_ipv6() && !has_ipv6_address {
                log::info!(
                    "ignoring VPN IPv6 DNS server {:?} because the server did not assign an IPv6 address",
                    value
                );
                continue;
            }
            let server = ip.to_string();
            if servers.contains(&server) {
                continue;
            }
            let route = dns_host_route(ip);
            split_servers.push(server.clone());
            servers.push(server);
            routes.push(route);
        }
    }
    if let Some(central_dns) = central_dns {
        if let Ok(ip) = central_dns.dnat_ip.trim().parse::<IpAddr>() {
            if !ip.is_ipv6() || has_ipv6_address {
                let server = ip.to_string();
                if !split_servers.contains(&server) {
                    split_servers.insert(0, server.clone());
                }
                let route = dns_host_route(ip);
                if !routes.contains(&route) {
                    routes.push(route);
                }
            }
        }
    }
    NetstackDnsConfig {
        servers: servers.join(","),
        split_servers,
        routes,
    }
}

fn dns_host_route(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(_) => format!("{ip}/32"),
        IpAddr::V6(_) => format!("{ip}/128"),
    }
}

fn normalize_dns_records(
    records: Option<std::collections::BTreeMap<String, Vec<String>>>,
) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut normalized = std::collections::BTreeMap::new();
    for (name, values) in records.unwrap_or_default() {
        let name = normalize_dns_name(&name);
        if !name.is_empty() {
            normalized
                .entry(name)
                .or_insert_with(Vec::new)
                .extend(values);
        }
    }
    normalized
}

fn merge_dns_records(
    target: &mut std::collections::BTreeMap<String, Vec<String>>,
    source: Option<std::collections::BTreeMap<String, Vec<String>>>,
) {
    for (name, values) in normalize_dns_records(source) {
        let target_values = target.entry(name).or_default();
        for value in values {
            if !target_values.contains(&value) {
                target_values.push(value);
            }
        }
    }
}

fn dynamic_dns_routes(policy: &NetstackDnsPolicy, has_ipv6_address: bool) -> Vec<String> {
    let mut routes = Vec::new();
    for values in policy
        .exact_v4
        .values()
        .chain(policy.exact_v6.values())
        .chain(policy.wildcard_v4.values())
        .chain(policy.suffix_v4.values())
    {
        for value in values {
            let value = value.split('/').next().unwrap_or(value).trim();
            let Ok(ip) = value.parse::<IpAddr>() else {
                continue;
            };
            if ip.is_ipv6() && !has_ipv6_address {
                continue;
            }
            let route = dns_host_route(ip);
            if !routes.contains(&route) {
                routes.push(route);
            }
        }
    }
    routes
}

async fn resolve_additional_domains(domains: &[String], has_ipv6_address: bool) -> Vec<String> {
    let mut routes = Vec::new();
    for configured_domain in domains {
        let domain = configured_domain.trim();
        if domain.is_empty() {
            log::warn!("ignoring empty vpn_additional_domains entry");
            continue;
        }

        match tokio::net::lookup_host((domain, 0)).await {
            Ok(addresses) => {
                let mut domain_routes = Vec::new();
                for address in addresses {
                    let ip = address.ip();
                    if ip.is_ipv6() && !has_ipv6_address {
                        continue;
                    }
                    let route = match ip {
                        std::net::IpAddr::V4(_) => format!("{ip}/32"),
                        std::net::IpAddr::V6(_) => format!("{ip}/128"),
                    };
                    if !domain_routes.contains(&route) {
                        domain_routes.push(route);
                    }
                }
                if domain_routes.is_empty() {
                    log::warn!(
                        "vpn_additional_domains entry {:?} returned no usable addresses",
                        domain
                    );
                } else {
                    log::info!(
                        "resolved additional VPN domain {:?} to {:?}",
                        domain,
                        domain_routes
                    );
                }
                for route in domain_routes {
                    if !routes.contains(&route) {
                        routes.push(route);
                    }
                }
            }
            Err(err) => {
                log::warn!(
                    "failed to resolve vpn_additional_domains entry {:?}: {}",
                    domain,
                    err
                );
            }
        }
    }
    routes
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; SIGN_HASH_OUTPUT_SIZE] {
    let mut key_block = [0u8; SIGN_HASH_BLOCK_SIZE];
    if key.len() > SIGN_HASH_BLOCK_SIZE {
        key_block[..SIGN_HASH_OUTPUT_SIZE].copy_from_slice(&sha2::Sha256::digest(key));
    } else {
        key_block[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; SIGN_HASH_BLOCK_SIZE];
    let mut opad = [0x5cu8; SIGN_HASH_BLOCK_SIZE];
    for i in 0..SIGN_HASH_BLOCK_SIZE {
        ipad[i] ^= key_block[i];
        opad[i] ^= key_block[i];
    }

    let mut inner = sha2::Sha256::new();
    inner.update(ipad);
    inner.update(data);
    let inner = inner.finalize();

    let mut outer = sha2::Sha256::new();
    outer.update(opad);
    outer.update(inner);
    outer.finalize().into()
}

fn hkdf_sha256(secret: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let zero_salt = [0u8; SIGN_HASH_OUTPUT_SIZE];
    let prk = if salt.is_empty() {
        hmac_sha256(&zero_salt, secret)
    } else {
        hmac_sha256(salt, secret)
    };

    let mut okm = Vec::with_capacity(len);
    let mut previous = Vec::new();
    let mut counter = 1u8;
    while okm.len() < len {
        let mut input = Vec::with_capacity(previous.len() + info.len() + 1);
        input.extend_from_slice(&previous);
        input.extend_from_slice(info);
        input.push(counter);
        previous = hmac_sha256(&prk, &input).to_vec();
        okm.extend_from_slice(&previous);
        counter = counter.wrapping_add(1);
    }
    okm.truncate(len);
    okm
}

fn write_pb_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8 & 0x7f) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn write_pb_field_varint(field: u64, value: u64, out: &mut Vec<u8>) {
    write_pb_varint(field << 3, out);
    write_pb_varint(value, out);
}

fn write_pb_field_bytes(field: u64, value: &[u8], out: &mut Vec<u8>) {
    write_pb_varint((field << 3) | 2, out);
    write_pb_varint(value.len() as u64, out);
    out.extend_from_slice(value);
}

fn encode_sign_header(signing_input_params: u64, signing_result: &[u8]) -> String {
    let mut body = Vec::with_capacity(40);
    write_pb_field_varint(1, SIGN_ROOT_KEY_VERSION, &mut body);
    write_pb_field_varint(3, signing_input_params, &mut body);
    write_pb_field_bytes(4, signing_result, &mut body);

    use base64::Engine;
    format!(
        "v1;{}",
        base64::engine::general_purpose::STANDARD.encode(body)
    )
}

fn corplink_client_builder() -> ClientBuilder {
    ClientBuilder::new()
        // CorpLink deployments may use certificates signed by their own CA.
        .danger_accept_invalid_certs(true)
        // for debug
        // .proxy(reqwest::Proxy::all("socks5://192.168.111.233:8001").unwrap())
        .user_agent(corplink_user_agent())
        .timeout(Duration::from_millis(10000))
}

pub struct Client {
    conf: Config,
    cookie: Arc<CookieStoreMutex>,
    c: reqwest::Client,
    probe_client: reqwest::Client,
    api_url: ApiUrl,
    date_offset_sec: i32,
    vpn_push_events: Option<broadcast::Sender<WebSocketEvent>>,
    vpn_push_task: Option<JoinHandle<()>>,
    vpn_push_cookie_fingerprint: Option<HashMap<String, Vec<u8>>>,
    automatic_recovery: bool,
}

type VpnPushWebSocket = WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

#[derive(Clone)]
struct VpnPushConnector {
    api_url: ApiUrl,
    cookie: Arc<CookieStoreMutex>,
    server_url: Url,
    server_time_offset_sec: i32,
    device_cookie_header: String,
}

impl VpnPushConnector {
    fn build_request(&self) -> Result<WebSocketRequest<()>> {
        let websocket_url = self
            .api_url
            .get_websocket_url(self.server_time_offset_sec)?;
        let mut request = websocket_url
            .into_client_request()
            .context("failed to build VPN push WebSocket request")?;

        let shared_cookies = ReqwestCookieStore::cookies(self.cookie.as_ref(), &self.server_url)
            .map(|cookies| {
                cookies
                    .to_str()
                    .context("invalid Cookie header for VPN push WebSocket")
                    .map(str::to_string)
            })
            .transpose()?;
        let cookies = match shared_cookies {
            Some(shared) if !shared.is_empty() => {
                format!("{}; {shared}", self.device_cookie_header)
            }
            _ => self.device_cookie_header.clone(),
        };
        if !cookies.is_empty() {
            request.headers_mut().insert(
                websocket_header::COOKIE,
                WebSocketHeaderValue::from_str(&cookies)
                    .context("invalid Cookie header for VPN push WebSocket")?,
            );
        }
        request.headers_mut().insert(
            websocket_header::ORIGIN,
            WebSocketHeaderValue::from_str(&self.server_url.origin().ascii_serialization())
                .context("invalid Origin header for VPN push WebSocket")?,
        );
        request.headers_mut().insert(
            websocket_header::USER_AGENT,
            WebSocketHeaderValue::from_static("Go-http-client/1.1"),
        );
        Ok(request)
    }

    async fn connect(&self) -> Result<VpnPushWebSocket> {
        let request = self.build_request()?;
        if let Some(cookie_header) = request.headers().get(websocket_header::COOKIE) {
            let mut cookie_names = cookie_header
                .to_str()
                .context("invalid Cookie header for VPN push WebSocket")?
                .split(';')
                .map(str::trim)
                .filter_map(|item| item.split_once('=').map(|(name, _)| name.to_string()))
                .collect::<Vec<_>>();
            cookie_names.sort();
            cookie_names.dedup();
            log::info!("VPN push WebSocket handshake cookies: {cookie_names:?}");
        }
        let (websocket, response) = connect_async(request)
            .await
            .context("failed to connect VPN push WebSocket")?;
        log::info!(
            "VPN push WebSocket connected with status {}",
            response.status()
        );
        Ok(websocket)
    }
}

struct VpnProbeResponse {
    latency_ms: i64,
    set_cookie_headers: Vec<header::HeaderValue>,
}

struct SelectedVpn {
    vpn: RespVpnInfo,
    set_cookie_headers: Vec<header::HeaderValue>,
}

unsafe impl Send for Client {}

unsafe impl Sync for Client {}

impl Drop for Client {
    fn drop(&mut self) {
        if let Some(task) = self.vpn_push_task.take() {
            task.abort();
        }
    }
}

pub async fn get_company_url(code: &str) -> anyhow::Result<RespCompany> {
    let c = ClientBuilder::new()
        // allow invalid certs because this cert is signed by corplink
        .danger_accept_invalid_certs(true)
        .build()
        .context("build client")?;
    let mut m = Map::new();
    m.insert("code".to_string(), json!(code));
    let body = serde_json::to_string(&m).context("serialize company request body")?;

    let resp = c
        .post(URL_GET_COMPANY)
        .body(body)
        .send()
        .await
        .context("get company")?
        .json::<Resp<RespCompany>>()
        .await
        .context("parse company resp")?;
    match resp.code {
        0 => resp.data.context("company response missing data"),
        _ => Err(anyhow!(resp
            .message
            .unwrap_or_else(|| "failed to fetch company info".to_string()))),
    }
}

impl Client {
    fn go_query_escape(value: &str) -> String {
        let mut url = Url::parse("https://device.invalid/").expect("static URL is valid");
        url.query_pairs_mut().append_pair("", value);
        url.query()
            .and_then(|query| query.strip_prefix('='))
            .unwrap_or_default()
            .to_string()
    }

    fn device_cookie_header_for_config(conf: &Config) -> Result<String> {
        let device_id = conf
            .device_id
            .as_deref()
            .context("device_id missing in config")?;
        let device_name = conf
            .device_name
            .as_deref()
            .context("device_name missing in config")?;
        Ok(format!(
            "device_id={}; device_name={}",
            Self::go_query_escape(device_id),
            Self::go_query_escape(device_name)
        ))
    }

    fn websocket_device_cookie_header_for_config(conf: &Config) -> Result<String> {
        let device_id = conf
            .device_id
            .as_deref()
            .context("device_id missing in config")?;
        let device_name = conf
            .device_name
            .as_deref()
            .context("device_name missing in config")?;
        Ok(format!(
            "device_id={}; HttpOnly; Secure; device_name={}; HttpOnly; Secure",
            Self::go_query_escape(device_id),
            Self::go_query_escape(device_name)
        ))
    }

    pub fn new(conf: Config) -> Result<Client> {
        let f = conf.conf_file.clone().context("config file path missing")?;
        let interface_name = conf
            .interface_name
            .clone()
            .context("interface name missing in config")?;
        let dir = match path::Path::new(&f).parent() {
            Some(dir) => dir,
            None => path::Path::new("."),
        };
        let cookie_file = dir.join(format!("{}_{}", interface_name, COOKIE_FILE_SUFFIX));
        log::info!("cookie file is: {}", cookie_file.to_string_lossy());

        let needs_fresh_login = matches!(conf.state.as_ref(), None | Some(State::Init));
        let cookie_store = if needs_fresh_login {
            CookieStore::default()
        } else {
            let file = fs::File::open(&cookie_file).map(io::BufReader::new);
            match file {
                Ok(file) => CookieStore::load_json_all(file).unwrap_or_else(|e| {
                    log::warn!(
                        "failed to load cookie store from {}, using empty store: {e}",
                        cookie_file.display()
                    );
                    CookieStore::default()
                }),
                Err(_) => CookieStore::default(),
            }
        };
        let has_expired = cookie_store.iter_any().any(|cookie| cookie.is_expired());
        if has_expired {
            log::info!("some cookies are expired");
        }

        let mut headers = header::HeaderMap::new();

        if let Some(server) = conf.server.as_ref() {
            let server_url = Url::from_str(server.as_str())
                .with_context(|| format!("invalid server url: {server}"))?;
            if let Some(domain) = server_url.domain().or_else(|| server_url.host_str()) {
                if let Some(csrf_token) = cookie_store.get(domain, "/", "csrf-token") {
                    let value = header::HeaderValue::from_str(csrf_token.value())
                        .context("invalid csrf-token header value")?;
                    headers.insert("csrf-token", value);
                }
            }
        }

        let cookie_store = Arc::new(CookieStoreMutex::new(cookie_store));

        // Keep probe responses out of the shared cookie store until an endpoint is selected.
        let probe_client = corplink_client_builder()
            .default_headers(headers.clone())
            .build()
            .context("build VPN probe HTTP client")?;
        let c = corplink_client_builder()
            .cookie_provider(Arc::clone(&cookie_store))
            .default_headers(headers)
            .build()
            .context("build http client")?;
        let conf_bak = conf.clone();
        Ok(Client {
            conf,
            cookie: Arc::clone(&cookie_store),
            c,
            probe_client,
            api_url: ApiUrl::new(&conf_bak)?,
            date_offset_sec: 0,
            vpn_push_events: None,
            vpn_push_task: None,
            vpn_push_cookie_fingerprint: None,
            automatic_recovery: false,
        })
    }

    async fn change_state(&mut self, state: State) -> Result<()> {
        self.conf.state = Some(state);
        self.conf.save().await?;
        Ok(())
    }

    fn save_cookie(&self) -> Result<()> {
        let f = self
            .conf
            .conf_file
            .as_ref()
            .context("config file path missing")?;
        let interface_name = self
            .conf
            .interface_name
            .as_ref()
            .context("interface name missing in config")?;
        let dir = match path::Path::new(f).parent() {
            Some(dir) => dir,
            None => path::Path::new("."),
        };
        let cookie_file = dir.join(format!("{}_{}", interface_name, COOKIE_FILE_SUFFIX));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .append(false)
            .open(&cookie_file)
            .map(io::BufWriter::new)
            .with_context(|| {
                format!(
                    "failed to open cookie file for writing: {}",
                    cookie_file.display()
                )
            })?;
        let c = self
            .cookie
            .lock()
            .map_err(|e| anyhow!("failed to lock cookie store: {e}"))?;
        c.save_json(&mut file)
            .or_else(|e| bail!("failed to persist cookies to disk: {e}"))?;
        Ok(())
    }

    fn shared_cookie_header_for_url(&self, url: &Url) -> Result<Option<header::HeaderValue>> {
        Ok(ReqwestCookieStore::cookies(self.cookie.as_ref(), url))
    }

    fn custom_device_cookie_header(&self) -> Result<header::HeaderValue> {
        let value = Self::device_cookie_header_for_config(&self.conf)?;
        header::HeaderValue::from_str(&value).context("invalid device Cookie header")
    }

    fn join_cookie_headers(
        first: Option<header::HeaderValue>,
        second: Option<header::HeaderValue>,
    ) -> Result<Option<header::HeaderValue>> {
        let values = [first, second]
            .into_iter()
            .flatten()
            .map(|value| {
                value
                    .to_str()
                    .context("invalid Cookie header")
                    .map(str::to_string)
            })
            .collect::<Result<Vec<_>>>()?;
        if values.is_empty() {
            return Ok(None);
        }
        Ok(Some(
            header::HeaderValue::from_str(&values.join("; "))
                .context("invalid joined Cookie header")?,
        ))
    }

    fn cookie_header_for_url(&self, url: &Url) -> Result<Option<header::HeaderValue>> {
        Self::join_cookie_headers(
            Some(self.custom_device_cookie_header()?),
            self.shared_cookie_header_for_url(url)?,
        )
    }

    fn cookie_fingerprint_from_header(
        header: &header::HeaderValue,
    ) -> Result<HashMap<String, Vec<u8>>> {
        let mut fingerprint = HashMap::new();
        for item in header
            .to_str()
            .context("invalid Cookie header")?
            .split(';')
            .map(str::trim)
        {
            let Some((name, value)) = item.split_once('=') else {
                continue;
            };
            fingerprint.insert(
                name.to_string(),
                sha2::Sha256::digest(value.as_bytes()).to_vec(),
            );
        }
        Ok(fingerprint)
    }

    fn cookie_fingerprint_for_url(&self, url: &Url) -> Result<HashMap<String, Vec<u8>>> {
        let header = self
            .cookie_header_for_url(url)?
            .context("Cookie header missing")?;
        Self::cookie_fingerprint_from_header(&header)
    }

    fn log_vpn_push_cookie_changes(&self, stage: &str) -> Result<()> {
        let Some(previous) = self.vpn_push_cookie_fingerprint.as_ref() else {
            return Ok(());
        };
        let current = self.cookie_fingerprint_for_url(&self.server_url()?)?;
        let mut added = current
            .keys()
            .filter(|name| !previous.contains_key(*name))
            .cloned()
            .collect::<Vec<_>>();
        let mut removed = previous
            .keys()
            .filter(|name| !current.contains_key(*name))
            .cloned()
            .collect::<Vec<_>>();
        let mut changed = current
            .iter()
            .filter(|(name, value)| previous.get(*name).is_some_and(|old| old != *value))
            .map(|(name, _)| name.clone())
            .collect::<Vec<_>>();
        added.sort();
        removed.sort();
        changed.sort();
        if added.is_empty() && removed.is_empty() && changed.is_empty() {
            log::info!("VPN push WebSocket Cookie identity unchanged at {stage}");
        } else {
            log::warn!(
                "VPN push WebSocket Cookie identity changed at {stage}: added={added:?}, removed={removed:?}, changed={changed:?}"
            );
        }
        Ok(())
    }

    fn server_url(&self) -> Result<Url> {
        let server_url = self
            .conf
            .server
            .as_ref()
            .context("server url is required")?;
        Url::from_str(server_url).with_context(|| format!("invalid server url: {server_url}"))
    }

    fn merge_cookie_headers(
        primary: Option<header::HeaderValue>,
        secondary: Option<header::HeaderValue>,
    ) -> Result<Option<header::HeaderValue>> {
        let mut cookies: Vec<(String, String)> = Vec::new();
        for header in [primary, secondary].into_iter().flatten() {
            for cookie in header
                .to_str()
                .context("invalid Cookie header")?
                .split(';')
                .map(str::trim)
                .filter(|cookie| !cookie.is_empty())
            {
                let Some((name, _)) = cookie.split_once('=') else {
                    continue;
                };
                if let Some(index) = cookies.iter().position(|(existing, _)| existing == name) {
                    cookies.remove(index);
                }
                cookies.push((name.to_string(), cookie.to_string()));
            }
        }

        if cookies.is_empty() {
            return Ok(None);
        }
        let value = cookies
            .into_iter()
            .map(|(_, cookie)| cookie)
            .collect::<Vec<_>>()
            .join("; ");
        Ok(Some(
            header::HeaderValue::from_str(&value).context("invalid merged Cookie header")?,
        ))
    }

    fn cookie_header_for_request(
        &self,
        api: &ApiName,
        url: &Url,
    ) -> Result<Option<header::HeaderValue>> {
        let endpoint_cookies = self.shared_cookie_header_for_url(url)?;
        if matches!(api, ApiName::ConnectVPN) {
            let tenant_url = self.server_url()?;
            let shared_cookies = Self::merge_cookie_headers(
                self.shared_cookie_header_for_url(&tenant_url)?,
                endpoint_cookies,
            )?;
            return Self::join_cookie_headers(
                Some(self.custom_device_cookie_header()?),
                shared_cookies,
            );
        }
        Self::join_cookie_headers(Some(self.custom_device_cookie_header()?), endpoint_cookies)
    }

    fn csrf_token_for_url(&self, url: &Url) -> Result<Option<header::HeaderValue>> {
        self.cookie_value_for_url(url, "csrf-token")
            .and_then(|value| {
                value
                    .map(|value| {
                        header::HeaderValue::from_str(&value)
                            .context("invalid csrf-token header value")
                    })
                    .transpose()
            })
    }

    fn jwt_token_for_request(&self, api: &ApiName) -> Result<Option<header::HeaderValue>> {
        if !matches!(api, ApiName::ConnectVPN) {
            return Ok(None);
        }
        let server_url = self.server_url()?;
        self.cookie_value_for_url(&server_url, "vpn-token")
            .and_then(|value| {
                value
                    .map(|value| {
                        header::HeaderValue::from_str(&value)
                            .context("invalid vpn-token header value")
                    })
                    .transpose()
            })
    }

    fn cookie_value_for_url(&self, url: &Url, name: &str) -> Result<Option<String>> {
        let cookie_store = self
            .cookie
            .lock()
            .map_err(|e| anyhow!("failed to lock cookie store: {e}"))?;
        let Some(domain) = url.domain().or_else(|| url.host_str()) else {
            return Ok(None);
        };
        Ok(cookie_store
            .get(domain, "/", name)
            .map(|cookie| cookie.value().to_string()))
    }

    fn signing_input_params(api: &ApiName) -> Option<u64> {
        match api {
            ApiName::ListVPN => Some(510),
            ApiName::ConnectVPN => Some(542),
            _ => None,
        }
    }

    fn sign_request(
        &self,
        api: &ApiName,
        method: &str,
        url: &Url,
        body: Option<&str>,
        cookie_header: Option<&header::HeaderValue>,
        csrf_token: Option<&header::HeaderValue>,
        jwt_token: Option<&header::HeaderValue>,
    ) -> Result<Option<String>> {
        let Some(signing_input_params) = Self::signing_input_params(api) else {
            return Ok(None);
        };
        let device_id = self
            .conf
            .device_id
            .as_deref()
            .context("device_id missing in config; required for request signing")?;
        let info = format!("{}|{}", self.conf.company_name, device_id);
        let key = hkdf_sha256(SIGN_SECRET, &[], info.as_bytes(), SIGN_HASH_OUTPUT_SIZE);

        let cookie = cookie_header
            .map(|value| value.to_str().context("invalid Cookie header for signing"))
            .transpose()?
            .unwrap_or("");
        let csrf = csrf_token
            .map(|value| {
                value
                    .to_str()
                    .context("invalid csrf-token header for signing")
            })
            .transpose()?
            .unwrap_or("");
        let body_hash = body
            .filter(|body| !body.is_empty())
            .map(|body| sha2::Sha256::digest(body.as_bytes()).to_vec())
            .unwrap_or_default();
        let jwt = jwt_token
            .map(|value| {
                value
                    .to_str()
                    .context("invalid jwt-token header for signing")
            })
            .transpose()?
            .unwrap_or("");
        let fields: [&[u8]; 10] = [
            b"",
            method.as_bytes(),
            url.path().as_bytes(),
            url.query().unwrap_or("").as_bytes(),
            body_hash.as_slice(),
            cookie.as_bytes(),
            b"",
            csrf.as_bytes(),
            b"",
            jwt.as_bytes(),
        ];

        let mut canonical = Vec::new();
        for (index, value) in fields.iter().enumerate().skip(1) {
            if (signing_input_params & (1 << index)) != 0 {
                canonical.extend_from_slice(value);
            }
        }

        let signing_result = hmac_sha256(&key, &canonical);
        Ok(Some(encode_sign_header(
            signing_input_params,
            &signing_result,
        )))
    }

    async fn request<T: DeserializeOwned + fmt::Debug>(
        &mut self,
        api: ApiName,
        body: Option<Map<String, Value>>,
    ) -> Result<Resp<T>> {
        let url = self
            .api_url
            .get_api_url_with_offset(&api, self.date_offset_sec);
        self.request_at(api, url, body).await
    }

    async fn request_at<T: DeserializeOwned + fmt::Debug>(
        &mut self,
        api: ApiName,
        url: String,
        body: Option<Map<String, Value>>,
    ) -> Result<Resp<T>> {
        let sensitive_qr_request = matches!(&api, ApiName::LoginQrToken | ApiName::LoginQrCheck);
        let sensitive_response = sensitive_qr_request || matches!(&api, ApiName::Setting);
        let parsed_url = Url::from_str(&url).with_context(|| format!("invalid url for {api:?}"))?;
        let body = body
            .map(|body| {
                serde_json::to_string(&body)
                    .with_context(|| format!("failed to serialize request body for {api:?}"))
            })
            .transpose()?;
        let method = if body.is_some() { "POST" } else { "GET" };
        let cookie_header = self.cookie_header_for_request(&api, &parsed_url)?;
        let csrf_token = self.csrf_token_for_url(&parsed_url)?;
        let jwt_token = self.jwt_token_for_request(&api)?;
        let sign_header = self.sign_request(
            &api,
            method,
            &parsed_url,
            body.as_deref(),
            cookie_header.as_ref(),
            csrf_token.as_ref(),
            jwt_token.as_ref(),
        )?;

        let mut rb = match body {
            Some(body) => self
                .c
                .post(url)
                .header(header::CONTENT_TYPE, "application/json")
                .body(body),
            None => self.c.get(url),
        };
        if let Some(cookie_header) = cookie_header {
            rb = rb.header(header::COOKIE, cookie_header);
        }
        if let Some(csrf_token) = csrf_token {
            rb = rb.header("csrf-token", csrf_token);
        }
        if let Some(jwt_token) = jwt_token {
            rb = rb.header("jwt-token", jwt_token);
        }
        if let Some(sign_header) = sign_header {
            rb = rb.header("sign", sign_header);
        }

        let resp = if sensitive_qr_request {
            rb.send()
                .await
                .map_err(|_| anyhow!("request {api:?} failed"))?
        } else {
            rb.send()
                .await
                .with_context(|| format!("request {api:?} failed"))?
        };

        if !resp.status().is_success() {
            if self.automatic_recovery {
                if resp.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
                    return Err(RecoveryRateLimited.into());
                }
                if matches!(
                    resp.status(),
                    reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
                ) {
                    return Err(RecoveryAuthenticationRequired.into());
                }
                bail!("VPN recovery API returned HTTP status {}", resp.status());
            }
            let msg = format!("logout because of bad resp code: {}", resp.status());
            self.handle_logout_err(msg).await?;
        }

        self.parse_time_offset_from_date_header(&resp);

        let mut set_cookie_names = resp
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .filter_map(|value| value.split_once('=').map(|(name, _)| name.to_string()))
            .collect::<Vec<_>>();
        set_cookie_names.sort();
        set_cookie_names.dedup();
        if !set_cookie_names.is_empty() {
            log::info!("api {api:?} updated cookies: {set_cookie_names:?}");
            self.save_cookie()?;
        }
        let text = resp
            .text()
            .await
            .with_context(|| format!("failed to read response body for api {api:?}"))?;
        // Parse the envelope generically first. When the server-side session has
        // expired the server returns a non-zero code (e.g. 101) with a `data`
        // whose shape doesn't match T (ListVPN, for instance, gets an object where
        // it expects an array). Deserializing straight into Resp<T> would fail here
        // and bypass the code-based logout/retry handling, leaving a stale-session
        // run dead with a confusing parse error. So only coerce `data` into T once
        // we know code == 0; otherwise keep the code/message so callers can react.
        let raw: Resp<Value> = if sensitive_qr_request {
            serde_json::from_str(&text)
                .with_context(|| format!("failed to parse response envelope for api {api:?}"))?
        } else {
            serde_json::from_str(&text).with_context(|| {
                format!("failed to parse response envelope for api {api:?}: {text}")
            })?
        };
        let data = match (raw.code, raw.data) {
            (0, Some(v)) => Some(
                serde_json::from_value::<T>(v)
                    .with_context(|| format!("failed to parse response data for api {api:?}"))?,
            ),
            _ => None,
        };
        let resp = Resp::<T> {
            code: raw.code,
            message: raw.message,
            data,
            action: raw.action,
        };
        if sensitive_response {
            log::debug!("api {:#?} response code: {}", api, resp.code);
        } else {
            log::debug!("api {:#?} resp: {:#?}", api, resp);
        }
        Ok(resp)
    }

    fn parse_time_offset_from_date_header(&mut self, resp: &Response) {
        let headers = resp.headers();
        if let Some(date) = headers.get("date") {
            match date.to_str() {
                Ok(date) => match httpdate::parse_http_date(date) {
                    Ok(date) => {
                        let now = SystemTime::now();
                        self.date_offset_sec = if now < date {
                            let date_offset = date
                                .duration_since(now)
                                .unwrap_or_else(|_| Duration::from_secs(0));
                            date_offset.as_secs().try_into().unwrap_or_default()
                        } else {
                            let date_offset = now
                                .duration_since(date)
                                .unwrap_or_else(|_| Duration::from_secs(0));
                            let offset: i32 = date_offset.as_secs().try_into().unwrap_or_default();
                            -offset
                        };
                    }
                    Err(e) => {
                        log::warn!("failed to parse date in header, ignore it: {}", e);
                    }
                },
                Err(e) => log::warn!("failed to read date header: {}", e),
            }
        }
    }

    pub fn need_login(&self) -> bool {
        matches!(self.conf.state.as_ref(), None | Some(State::Init))
    }

    async fn check_tps_token(&mut self, token: &String) -> Result<String> {
        // tps confirmed, try to login with token
        let mut m = Map::new();
        m.insert("token".to_string(), json!(token));

        let resp = self
            .request::<RespLogin>(ApiName::TpsTokenCheck, Some(m))
            .await?;
        match resp.code {
            0 => resp
                .data
                .context("tps token check missing redirect url")
                .map(|d| d.url),
            _ => {
                let msg = resp
                    .message
                    .unwrap_or_else(|| "tps token check failed".to_string());
                bail!(msg)
            }
        }
    }

    async fn get_otp_uri_from_tps(
        &mut self,
        method: &str,
        url: &String,
        token: &String,
    ) -> Result<String> {
        log::info!("received third-party login token");
        log::info!("please scan the QR code or visit the following link to auth corplink:\n{url}");
        match TerminalQrCode::from_bytes(url.as_bytes()) {
            Ok(qr) => qr.print(),
            Err(e) => {
                log::warn!("failed to generate qr code: {e}");
            }
        }
        match method {
            PLATFORM_LARK | PLATFORM_OIDC => {
                log::info!("press enter if you finish auth");
                let stdin = io::stdin();
                stdin.lines().next();
                self.check_tps_token(token).await
            }
            _ => {
                // TODO: add all tps login support
                bail!("unsupported platform, please contact the developer");
            }
        }
    }

    async fn corplink_login(&mut self) -> Result<String> {
        if self.conf.platform.as_deref() == Some(PLATFORM_CORPLINK_EMAIL) {
            log::info!("try to login with code from email");
            return self.login_with_email_v1().await;
        }

        let resp = self.get_corplink_login_method().await?;
        for method in resp.auth {
            match method.as_str() {
                "password" => {
                    if let Some(password) = &self.conf.password {
                        if !password.is_empty() {
                            log::info!("try to login with password");
                            return self.login_with_password(PLATFORM_CORPLINK).await;
                        }
                    }
                    log::info!("no password provided, trying other methods");
                    continue;
                }
                "email" => {
                    log::info!("try to login with code from email");
                    return self.login_with_email().await;
                }
                _ => {
                    log::info!("unsupported method {method}, trying other methods");
                }
            }
        }
        bail!("failed to login with corplink")
    }

    async fn ldap_login(&mut self) -> Result<String> {
        // I don't know why but we must get login method before login
        let resp = self.get_corplink_login_method().await?;
        for method in resp.auth {
            if method != "password" {
                continue;
            }
            if let Some(password) = &self.conf.password {
                return if !password.is_empty() {
                    self.login_with_password(PLATFORM_LDAP).await
                } else {
                    bail!("no password provided")
                };
            }
        }
        bail!("failed to login with ldap")
    }

    fn is_platform_or_default(&self, platform: &str) -> bool {
        if let Some(p) = &self.conf.platform {
            return p.is_empty()
                || platform == p
                || ([PLATFORM_CORPLINK_EMAIL, PLATFORM_CORPLINK_QR].contains(&p.as_str())
                    && platform == PLATFORM_CORPLINK);
        }
        true
    }

    async fn request_otp_code(&mut self) -> Result<String> {
        let m = Map::new();
        let resp = self.request::<RespOtp>(ApiName::Otp, Some(m)).await?;
        match resp.code {
            0 => Ok(resp.data.context("otp response missing data")?.url),
            _ => {
                let msg = resp
                    .message
                    .unwrap_or_else(|| "request otp code failed".to_string());
                bail!(msg)
            }
        }
    }

    async fn get_otp_uri_by_otp(
        &mut self,
        tps_login: &HashMap<String, RespTpsLoginMethod>,
        method: &String,
    ) -> Result<String> {
        let url = self.get_otp_uri(tps_login, method).await?;
        if url.is_empty() {
            self.request_otp_code().await
        } else {
            Ok(url)
        }
    }
    async fn get_otp_uri(
        &mut self,
        tps_login: &HashMap<String, RespTpsLoginMethod>,
        method: &String,
    ) -> Result<String> {
        if let Some(resp) = tps_login
            .get(method)
            .filter(|_| self.is_platform_or_default(method))
        {
            log::info!("try to login with third party platform {method}");
            return self
                .get_otp_uri_from_tps(method, &resp.login_url, &resp.token)
                .await;
        }
        match method.as_str() {
            PLATFORM_CORPLINK => {
                if self.is_platform_or_default(PLATFORM_CORPLINK) {
                    log::info!("try to login with platform {PLATFORM_CORPLINK}");
                    return self.corplink_login().await;
                }
            }
            PLATFORM_LDAP => {
                if self.is_platform_or_default(PLATFORM_LDAP) {
                    log::info!("try to login with platform {PLATFORM_LDAP}");
                    return self.ldap_login().await;
                }
            }
            _ => {}
        }
        Ok(String::new())
    }

    // new feilian v1 login (/api/v1/login with AES-encrypted password).
    // opt-in via `"platform": "feilian_v1"`; the old login paths are untouched.
    async fn login_v1(&mut self) -> Result<()> {
        let password = self
            .conf
            .password
            .as_ref()
            .filter(|p| !p.is_empty())
            .context("platform feilian_v1 requires a password")?
            .clone();
        log::info!("try to login with platform feilian_v1");
        let enc = utils::feilian_v1_encrypt_password(&password);
        let mut m = Map::new();
        m.insert("login_scene".to_string(), json!(PLATFORM_CORPLINK));
        m.insert("account_type".to_string(), json!("userid"));
        m.insert("account".to_string(), json!(&self.conf.username));
        m.insert("password".to_string(), json!(enc));

        let resp = self
            .request::<RespLoginV1>(ApiName::LoginPasswordV1, Some(m))
            .await?;
        match resp.code {
            0 => {
                let data = resp.data.context("v1 login response missing data")?;
                if data.result != "success" {
                    bail!("v1 login returned unexpected result: {}", data.result);
                }
                log::info!("login success");
                self.change_state(State::Login).await?;

                // fetch the TOTP secret so 2fa codes can be generated locally,
                // mirroring the legacy login() flow. the v1 backend serves the
                // same /api/v2/p/otp endpoint and otpauth uri format.
                match self.request_otp_code().await {
                    Ok(otp_uri) if !otp_uri.is_empty() => {
                        let url = Url::parse(&otp_uri).context("failed to parse otp uri")?;
                        for (k, v) in url.query_pairs() {
                            if k == "secret" {
                                log::info!("received and stored 2fa token");
                                self.conf.code = Some(v.to_string());
                                self.conf.save().await?;
                                break;
                            }
                        }
                    }
                    Ok(_) => {
                        log::info!(
                            "no otp code from server, will ask for 2fa code when connecting"
                        );
                    }
                    Err(e) => log::warn!("failed to get otp code: {e}"),
                }
                Ok(())
            }
            _ => {
                let msg = resp
                    .message
                    .unwrap_or_else(|| "v1 login failed".to_string());
                bail!(msg)
            }
        }
    }

    // choose right login method and login
    pub async fn login(&mut self) -> Result<()> {
        if self.conf.platform.as_deref() == Some(PLATFORM_CORPLINK_V1) {
            return self.login_v1().await;
        }
        let resp = self.get_login_method().await?;
        if self.conf.platform.as_deref() == Some(PLATFORM_CORPLINK_QR) {
            return self.login_with_qr(&resp).await;
        }
        let tps_login_resp = self.get_tps_login_method().await?;
        let mut tps_login = HashMap::new();
        for resp in tps_login_resp {
            tps_login.insert(resp.alias.clone(), resp);
        }
        for method in resp.login_orders {
            let otp_uri = self.get_otp_uri_by_otp(&tps_login, &method).await;
            if let Err(e) = otp_uri {
                log::warn!("failed to login with method {method}: {e}");
                continue;
            }
            let otp_uri = otp_uri?;
            if otp_uri.is_empty() {
                log::info!("no otp code from server, will ask for 2fa code when connecting");
                self.change_state(State::Login).await?;
                return Ok(());
            }
            self.change_state(State::Login).await?;

            let url = Url::parse(&otp_uri).context("failed to parse otp uri")?;
            for (k, v) in url.query_pairs() {
                if k == "secret" {
                    log::info!("received and stored 2fa token");
                    self.conf.code = Some(v.to_string());
                    self.conf.save().await?;
                    break;
                }
            }

            if let Some(code) = &self.conf.code {
                if !code.is_empty() {
                    return Ok(());
                }
            }
            log::warn!("failed to get otp code");
            return Ok(());
        }
        bail!("no available login method, please provide a valid platform")
    }

    async fn get_login_method(&mut self) -> Result<RespLoginMethod> {
        let resp = self
            .request::<RespLoginMethod>(ApiName::LoginMethod, None)
            .await?;
        resp.data.context("login method response missing data")
    }

    // get 3rd party login methods and links, only lark(feishu) is tested
    async fn get_tps_login_method(&mut self) -> Result<Vec<RespTpsLoginMethod>> {
        let resp = self
            .request::<Vec<RespTpsLoginMethod>>(ApiName::TpsLoginMethod, None)
            .await?;
        Ok(resp.data.unwrap_or_default())
    }

    // get corplink login method, knowing result can be password or email
    async fn get_corplink_login_method(&mut self) -> Result<RespCorplinkLoginMethod> {
        let mut m = Map::new();
        m.insert("forget_password".to_string(), json!(false));
        m.insert("user_name".to_string(), json!(&self.conf.username));

        let resp = self
            .request::<RespCorplinkLoginMethod>(ApiName::CorplinkLoginMethod, Some(m))
            .await?;
        resp.data
            .context("corplink login method response missing data")
    }

    async fn login_with_password(&mut self, platform: &str) -> Result<String> {
        let mut password = self
            .conf
            .password
            .as_ref()
            .context("password is required for password login")?
            .clone();
        let mut m = Map::new();
        match platform {
            PLATFORM_LDAP => {
                m.insert("platform".to_string(), json!(PLATFORM_LDAP));
            }
            PLATFORM_CORPLINK => {
                if password.len() != 64 {
                    let mut sha = sha2::Sha256::new();
                    sha.update(password.as_bytes());
                    password = format!("{:x}", sha.finalize());
                } // else: password already convert to sha256sum
            }
            _ => {
                bail!("invalid platform {platform}")
            }
        }
        m.insert("password".to_string(), json!(password));
        m.insert("user_name".to_string(), json!(&self.conf.username));

        let resp = self
            .request::<RespLogin>(ApiName::LoginPassword, Some(m))
            .await?;
        match resp.code {
            0 => Ok(resp
                .data
                .context("password login response missing data")?
                .url),
            _ => {
                let msg = resp
                    .message
                    .unwrap_or_else(|| "login with password failed".to_string());
                bail!(msg)
            }
        }
    }

    async fn request_email_code(&mut self) -> Result<()> {
        let mut m = Map::new();
        m.insert("forget_password".to_string(), json!(false));
        m.insert("code_type".to_string(), json!("email"));
        m.insert("user_name".to_string(), json!(&self.conf.username));

        let resp = self
            .request::<Map<String, Value>>(ApiName::RequestEmailCode, Some(m))
            .await?;
        match resp.code {
            0 => Ok(()),
            _ => {
                let msg = resp
                    .message
                    .unwrap_or_else(|| "failed to request email code".to_string());
                bail!(msg)
            }
        }
    }

    async fn request_email_code_v1(&mut self) -> Result<()> {
        let mut m = Map::new();
        m.insert("account".to_string(), json!(&self.conf.username));
        m.insert("login_scene".to_string(), json!(PLATFORM_CORPLINK));
        m.insert("account_type".to_string(), json!("email"));
        m.insert("login_type".to_string(), json!("email"));

        let resp = self
            .request::<Map<String, Value>>(ApiName::RequestEmailCodeV1, Some(m))
            .await?;
        match resp.code {
            0 => Ok(()),
            _ => {
                let msg = resp
                    .message
                    .unwrap_or_else(|| "failed to request email code".to_string());
                bail!(msg)
            }
        }
    }

    async fn login_with_email_v1(&mut self) -> Result<String> {
        log::info!("try to request code for email");
        self.request_email_code_v1().await?;

        log::info!("input your code from email:");
        let input = utils::read_line().await?;
        let code = input.trim();
        let mut m = Map::new();
        m.insert("account".to_string(), json!(&self.conf.username));
        m.insert("login_scene".to_string(), json!(PLATFORM_CORPLINK));
        m.insert("account_type".to_string(), json!("email"));
        m.insert("login_type".to_string(), json!("email"));
        m.insert("code".to_string(), json!(code));

        let resp = self
            .request::<RespLoginV1>(ApiName::LoginEmailV1, Some(m))
            .await?;
        match resp.code {
            0 => {
                let data = resp.data.context("email login response missing data")?;
                if data.result != "success" {
                    bail!("email login returned unexpected result: {}", data.result);
                }
                Ok(String::new())
            }
            _ => {
                let msg = resp
                    .message
                    .unwrap_or_else(|| "failed to login with email code".to_string());
                bail!(msg)
            }
        }
    }

    async fn login_with_qr(&mut self, login_method: &RespLoginMethod) -> Result<()> {
        let scan_base = login_method
            .scan_code_login_url
            .as_deref()
            .context("server did not provide a QR login URL")?;
        let token_resp = self
            .request::<RespQrToken>(ApiName::LoginQrToken, None)
            .await?;
        if token_resp.code != 0 {
            bail!(
                "failed to request QR login token: {}",
                token_resp.message.unwrap_or_default()
            );
        }
        let token = token_resp
            .data
            .context("QR login token response missing data")?
            .token;

        let mut scan_url = Url::parse(scan_base).context("invalid QR login URL")?;
        scan_url.query_pairs_mut().append_pair("token", &token);
        log::info!("scan this QR code with the feilian mobile app and confirm login:");
        TerminalQrCode::from_bytes(scan_url.as_str().as_bytes())
            .context("failed to generate QR code")?
            .print();
        drop(scan_url);

        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if Instant::now() >= deadline {
                bail!("QR login timed out; request a new QR code")
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
            let check_url = self
                .api_url
                .get_qr_check_url_with_offset(&token, self.date_offset_sec)?;
            let resp = self
                .request_at::<RespQrCheck>(ApiName::LoginQrCheck, check_url, None)
                .await?;
            match resp.code {
                0 => {
                    let result = resp.data.unwrap_or(RespQrCheck {
                        result: String::new(),
                    });
                    if result.result == "success" {
                        log::info!("QR login success");
                        self.sign_required_agreement().await?;
                        self.change_state(State::Login).await?;
                        return Ok(());
                    }
                }
                1005 => continue,
                _ => {
                    bail!(
                        "QR login failed: {}",
                        resp.message
                            .unwrap_or_else(|| format!("code {}", resp.code))
                    )
                }
            }
        }
    }

    async fn sign_required_agreement(&mut self) -> Result<()> {
        let mut body = Map::new();
        body.insert("keys".to_string(), json!([0]));
        let response = self
            .request::<Value>(ApiName::AgreementSign, Some(body))
            .await?;
        if response.code != 0 {
            bail!(
                "failed to sign FeiLian agreement with error {}: {}",
                response.code,
                response.message.unwrap_or_default()
            );
        }
        Ok(())
    }

    async fn login_with_email(&mut self) -> Result<String> {
        // tell server to send code to email
        log::info!("try to request code for email");
        self.request_email_code().await?;

        log::info!("input your code from email:");
        let input = utils::read_line().await?;
        let code = input.trim();
        let mut m = Map::new();
        m.insert("forget_password".to_string(), json!(false));
        m.insert("code_type".to_string(), json!("email"));
        m.insert("code".to_string(), json!(code));
        m.insert("user_name".to_string(), json!(&self.conf.username));

        let resp = self
            .request::<RespLogin>(ApiName::LoginEmail, Some(m))
            .await?;
        match resp.code {
            0 => Ok(resp.data.context("email login response missing data")?.url),
            _ => bail!(format!(
                "failed to login with email code: {}",
                resp.message.unwrap_or_else(|| "unknown error".to_string())
            )),
        }
    }

    async fn handle_logout_err(&mut self, msg: String) -> Result<()> {
        if self.automatic_recovery {
            return Err(RecoveryAuthenticationRequired.into());
        }
        self.stop_vpn_push_websocket();
        {
            let mut cookie_store = self
                .cookie
                .lock()
                .map_err(|e| anyhow!("failed to lock cookie store: {e}"))?;
            cookie_store.clear();
        }
        self.save_cookie()
            .context("failed to clear stale login cookies")?;
        self.change_state(State::Init)
            .await
            .context("failed to reset state after logout")?;
        bail!("operation failed because of logout: {msg}")
    }

    async fn list_vpn(&mut self) -> Result<Vec<RespVpnInfo>> {
        let resp = self
            .request::<Vec<RespVpnInfo>>(ApiName::ListVPN, None)
            .await?;
        match resp.code {
            0 => resp.data.context("list vpn response missing data"),
            101 | VPN_SESSION_MISSING_CODE => {
                let msg = resp
                    .message
                    .unwrap_or_else(|| "logout required".to_string());
                self.handle_logout_err(msg).await?;
                unreachable!()
            }
            429 => Err(RecoveryRateLimited.into()),
            _ => bail!(format!(
                "failed to list vpn with error {}: {}",
                resp.code,
                resp.message.unwrap_or_default()
            )),
        }
    }

    async fn initialize_session_setting(&mut self) -> Result<()> {
        log::info!("initializing FeiLian session settings");
        let resp = self.request::<Value>(ApiName::Setting, None).await?;
        match resp.code {
            0 => {
                log::info!("FeiLian session settings initialized");
                Ok(())
            }
            101 | VPN_SESSION_MISSING_CODE => {
                let msg = resp
                    .message
                    .unwrap_or_else(|| "logout required".to_string());
                self.handle_logout_err(msg).await?;
                unreachable!()
            }
            429 => Err(RecoveryRateLimited.into()),
            _ => bail!(format!(
                "failed to initialize FeiLian session settings with error {}: {}",
                resp.code,
                resp.message.unwrap_or_default()
            )),
        }
    }

    async fn get_first_vpn_by_latency(&self, vpn_info: Vec<RespVpnInfo>) -> Option<SelectedVpn> {
        let mut fastest: Option<(i64, usize, SelectedVpn)> = None;

        let mut probes = vpn_info
            .into_iter()
            .enumerate()
            .map(|(index, vpn)| async move {
                let result = self.ping_vpn(&vpn.ip, vpn.api_port).await;
                (index, vpn, result)
            })
            .collect::<FuturesUnordered<_>>();

        while let Some((index, vpn, result)) = probes.next().await {
            match result {
                Ok(response) => {
                    log::info!(
                        "server name {}, latency {}ms",
                        if vpn.en_name.is_empty() {
                            &vpn.name
                        } else {
                            &vpn.en_name
                        },
                        response.latency_ms
                    );
                    let should_replace = match &fastest {
                        Some((latency, best_index, _)) => {
                            (response.latency_ms, index) < (*latency, *best_index)
                        }
                        None => true,
                    };
                    if should_replace {
                        fastest = Some((
                            response.latency_ms,
                            index,
                            SelectedVpn {
                                vpn,
                                set_cookie_headers: response.set_cookie_headers,
                            },
                        ));
                    }
                }
                Err(err) => {
                    log::warn!("failed to ping {}:{}: {}", vpn.ip, vpn.api_port, err);
                }
            }
        }
        fastest.map(|(_, _, vpn)| vpn)
    }

    async fn get_first_available_vpn(&self, vpn_info: Vec<RespVpnInfo>) -> Option<SelectedVpn> {
        // Probes finish out of order, but the default strategy follows server-list priority.
        let mut results = std::iter::repeat_with(|| None)
            .take(vpn_info.len())
            .collect::<Vec<_>>();
        let mut next_index = 0;
        let mut probes = vpn_info
            .into_iter()
            .enumerate()
            .map(|(index, vpn)| async move {
                let result = self.ping_vpn(&vpn.ip, vpn.api_port).await;
                (index, vpn, result)
            })
            .collect::<FuturesUnordered<_>>();

        while let Some((index, vpn, result)) = probes.next().await {
            results[index] = Some((vpn, result));

            while next_index < results.len() {
                let Some((vpn, result)) = results[next_index].take() else {
                    break;
                };
                next_index += 1;

                match result {
                    Ok(response) => {
                        log::info!(
                            "server name {}, latency {}ms",
                            if vpn.en_name.is_empty() {
                                &vpn.name
                            } else {
                                &vpn.en_name
                            },
                            response.latency_ms
                        );
                        return Some(SelectedVpn {
                            vpn,
                            set_cookie_headers: response.set_cookie_headers,
                        });
                    }
                    Err(err) => {
                        log::warn!("failed to ping {}:{}: {}", vpn.ip, vpn.api_port, err);
                    }
                }
            }
        }
        None
    }

    fn vpn_endpoint_url(&self, host: &str, api_port: u16) -> Result<Url> {
        let server_url = self
            .conf
            .server
            .as_ref()
            .context("server url is required to configure vpn endpoint")?;
        let server_url = Url::from_str(server_url)
            .with_context(|| format!("invalid server url: {server_url}"))?;
        let mut endpoint_url = Url::parse(&format!("{}://localhost", server_url.scheme()))
            .context("failed to construct vpn endpoint URL")?;
        match host.parse::<IpAddr>() {
            Ok(ip) => endpoint_url
                .set_ip_host(ip)
                .map_err(|_| anyhow!("failed to set vpn endpoint IP"))?,
            Err(_) => endpoint_url
                .set_host(Some(host))
                .context("failed to set vpn endpoint host")?,
        }
        endpoint_url
            .set_port(Some(api_port))
            .map_err(|_| anyhow!("failed to set vpn endpoint port"))?;
        Ok(endpoint_url)
    }

    fn tenant_cookie_header(&self) -> Result<Option<header::HeaderValue>> {
        let server_url = self.server_url()?;
        self.cookie_header_for_url(&server_url)
    }

    fn prepare_vpn_endpoint(&mut self, ip: &str, api_port: u16) -> Result<Url> {
        let url = self.vpn_endpoint_url(ip, api_port)?;
        self.api_url.vpn_param.url = url.to_string().trim_end_matches('/').to_string();
        Ok(url)
    }

    fn store_vpn_probe_cookies(
        &self,
        headers: &[header::HeaderValue],
        endpoint_url: &Url,
    ) -> Result<()> {
        ReqwestCookieStore::set_cookies(self.cookie.as_ref(), &mut headers.iter(), endpoint_url);
        Ok(())
    }

    // ping vpn and return latency in ms. Will return Err on error
    async fn ping_vpn(&self, ip: &str, api_port: u16) -> Result<VpnProbeResponse> {
        let endpoint_url = self.vpn_endpoint_url(ip, api_port)?;
        let mut api_url = self.api_url.clone();
        api_url.vpn_param.url = endpoint_url.to_string().trim_end_matches('/').to_string();

        let mut request = self
            .probe_client
            .get(api_url.get_api_url_with_offset(&ApiName::PingVPN, self.date_offset_sec));
        if let Some(cookies) = self.tenant_cookie_header()? {
            request = request.header(header::COOKIE, cookies);
        }

        let started = Instant::now();
        let response = request.send().await.context("VPN probe request failed")?;
        let status = response.status();
        let set_cookie_headers = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .cloned()
            .collect();
        let body = response
            .text()
            .await
            .context("failed to read VPN probe response body")?;
        let latency_ms = started.elapsed().as_millis().min(i64::MAX as u128) as i64;

        if !status.is_success() {
            bail!("VPN probe returned HTTP status {status}");
        }
        let resp: Resp<Value> = serde_json::from_str(&body)
            .with_context(|| format!("failed to parse VPN probe response: {body}"))?;
        match resp.code {
            0 => Ok(VpnProbeResponse {
                latency_ms,
                set_cookie_headers,
            }),
            _ => bail!(format!(
                "failed to ping vpn with error {}: {}",
                resp.code,
                resp.message.unwrap_or_default()
            )),
        }
    }

    async fn fetch_peer_info(&mut self) -> Result<(RespWgInfo, String, String)> {
        let mut otp = String::new();
        if let Some(code) = &self.conf.code {
            if !code.is_empty() {
                let code = utils::b32_decode(code)?;
                let offset = self.date_offset_sec / TIME_STEP as i32;
                let raw_otp = totp_offset(code.as_slice(), offset);
                otp = format!("{:06}", raw_otp.code);
                log::info!("2fa code generated; {} seconds left", raw_otp.secs_left);
            }
        }
        if otp.is_empty() {
            let is_tps_login = matches!(
                self.conf.platform.as_deref(),
                Some(PLATFORM_LARK | PLATFORM_OIDC)
            );
            if is_tps_login {
                log::info!("use empty 2fa code (tps login already verified)");
            } else if matches!(
                self.conf.platform.as_deref(),
                Some(PLATFORM_CORPLINK_EMAIL | PLATFORM_CORPLINK_QR | PLATFORM_CORPLINK_V1)
            ) {
                log::info!("try current VPN MFA flow");
            } else if self.automatic_recovery {
                return Err(RecoveryAuthenticationRequired.into());
            } else {
                log::info!("input your 2fa code:");
                otp = utils::read_line().await?;
            }
        }
        let smac = default_interface_mac().await.unwrap_or_else(|| {
            log::warn!("could not determine the default interface MAC; sending an empty smac");
            String::new()
        });
        let route_mode = self.conf.route_mode.clone().unwrap_or_default();
        let (mut public_key, mut private_key) = utils::gen_wg_keypair();
        let m = vpn_connect_body(&public_key, &otp, &route_mode, &smac);
        let mut resp = self
            .request::<RespWgInfo>(ApiName::ConnectVPN, Some(m))
            .await?;
        if resp.code == VPN_MFA_REQUIRED_CODE {
            if self.automatic_recovery {
                return Err(RecoveryAuthenticationRequired.into());
            }
            self.complete_vpn_mfa((!otp.is_empty()).then_some(otp.as_str()))
                .await?;
            (public_key, private_key) = utils::gen_wg_keypair();
            let retry = vpn_connect_body(&public_key, "", &route_mode, &smac);
            resp = self
                .request::<RespWgInfo>(ApiName::ConnectVPN, Some(retry))
                .await?;
        }
        match resp.code {
            0 => Ok((
                resp.data.context("connect vpn response missing data")?,
                public_key,
                private_key,
            )),
            101 | VPN_SESSION_MISSING_CODE => {
                let msg = resp
                    .message
                    .unwrap_or_else(|| "logout required".to_string());
                self.handle_logout_err(msg).await?;
                unreachable!()
            }
            429 => Err(RecoveryRateLimited.into()),
            _ => bail!(format!(
                "failed to fetch peer info with error {}: {}",
                resp.code,
                resp.message.unwrap_or_default()
            )),
        }
    }

    pub async fn start_vpn_push_websocket(&mut self) -> Result<()> {
        if self
            .vpn_push_task
            .as_ref()
            .is_some_and(|task| !task.is_finished())
        {
            return Ok(());
        }
        self.stop_vpn_push_websocket();

        let server_url = self.server_url()?;
        let cookie_fingerprint = self.cookie_fingerprint_for_url(&server_url)?;
        let connector = VpnPushConnector {
            api_url: self.api_url.clone(),
            cookie: Arc::clone(&self.cookie),
            server_url,
            server_time_offset_sec: self.date_offset_sec,
            device_cookie_header: Self::websocket_device_cookie_header_for_config(&self.conf)?,
        };
        let websocket = connector.connect().await?;
        let (events, _) = broadcast::channel(32);
        let task_events = events.clone();
        let task = tokio::spawn(async move {
            maintain_vpn_push_websocket(connector, websocket, task_events).await;
        });
        self.vpn_push_events = Some(events);
        self.vpn_push_task = Some(task);
        self.vpn_push_cookie_fingerprint = Some(cookie_fingerprint);
        Ok(())
    }

    fn stop_vpn_push_websocket(&mut self) {
        if let Some(task) = self.vpn_push_task.take() {
            task.abort();
        }
        self.vpn_push_events = None;
        self.vpn_push_cookie_fingerprint = None;
    }

    async fn revoke_vpn_push(&mut self, message_id: &str) {
        let mut revoke = Map::new();
        revoke.insert("mfa_type".to_string(), json!("push"));
        revoke.insert("message_id".to_string(), json!(message_id));
        match self
            .request::<Map<String, Value>>(ApiName::VpnMfaRevoke, Some(revoke))
            .await
        {
            Ok(response) if response.code == 0 => {}
            Ok(response) => log::warn!(
                "failed to revoke VPN push confirmation with error {}: {}",
                response.code,
                response.message.unwrap_or_default()
            ),
            Err(error) => log::warn!("failed to revoke VPN push confirmation: {error}"),
        }
    }

    async fn complete_vpn_push_mfa(&mut self) -> Result<()> {
        // The WebSocket is started after the initial VPN list refresh and remains
        // alive for the Client lifetime. Like the official client, MFA only
        // subscribes to the already-running event stream before sending the push.
        let mut events = self
            .vpn_push_events
            .as_ref()
            .context("VPN push WebSocket is unavailable")?
            .subscribe();
        self.log_vpn_push_cookie_changes("before VPN push request")?;
        let mut push = Map::new();
        push.insert("mfa_type".to_string(), json!("push"));
        push.insert("mfa_scene".to_string(), json!(VPN_MFA_SCENE));
        let sent = self
            .request::<Map<String, Value>>(ApiName::VpnMfaPush, Some(push))
            .await?;
        if sent.code != 0 {
            bail!(
                "failed to send VPN push confirmation with error {}: {}",
                sent.code,
                sent.message.unwrap_or_default()
            );
        }
        self.log_vpn_push_cookie_changes("after VPN push request")?;
        let message_id = sent
            .data
            .as_ref()
            .and_then(|data| data.get("message_id"))
            .and_then(Value::as_str)
            .context("VPN push response missing message_id")?
            .to_string();
        log::info!("VPN push confirmation sent; approve it in FeiLian");

        let result =
            wait_for_vpn_push_confirmation(&mut events, &message_id, VPN_PUSH_CONFIRM_TIMEOUT)
                .await;
        match result {
            Ok(true) => Ok(()),
            Ok(false) => {
                self.revoke_vpn_push(&message_id).await;
                bail!(
                    "VPN push confirmation timed out after {} seconds",
                    VPN_PUSH_CONFIRM_TIMEOUT.as_secs()
                )
            }
            Err(error) => {
                self.revoke_vpn_push(&message_id).await;
                Err(error)
            }
        }
    }

    async fn complete_vpn_mfa(&mut self, existing_otp: Option<&str>) -> Result<()> {
        let methods = self
            .request::<RespVpnMfaType>(ApiName::VpnMfaType, None)
            .await?;
        if methods.code != 0 {
            bail!(
                "failed to get VPN MFA methods with error {}: {}",
                methods.code,
                methods.message.unwrap_or_default()
            );
        }
        let methods = methods.data.unwrap_or_default();
        let code_type = select_supported_vpn_mfa_type(&methods, self.conf.vpn_mfa_type.as_deref())
            .with_context(|| {
                format!(
                    "no supported VPN MFA method; server offered {:?}",
                    methods
                        .vpn_types
                        .iter()
                        .chain(methods.types.iter())
                        .collect::<Vec<_>>()
                )
            })?;

        if code_type == "push" {
            return self.complete_vpn_push_mfa().await;
        }

        let code = match code_type {
            "email" | "mobile" => {
                let mut send = Map::new();
                send.insert("mfa_scene".to_string(), json!(VPN_MFA_SCENE));
                send.insert("code_type".to_string(), json!(code_type));
                let sent = self
                    .request::<Map<String, Value>>(ApiName::VpnMfaSend, Some(send))
                    .await?;
                if sent.code != 0 {
                    bail!(
                        "failed to send VPN MFA code with error {}: {}",
                        sent.code,
                        sent.message.unwrap_or_default()
                    );
                }
                log::info!("input the VPN {code_type} verification code:");
                utils::read_line().await?
            }
            "otp" => match existing_otp {
                Some(code) => code.to_string(),
                None => {
                    log::info!("input your current FeiLian OTP code:");
                    utils::read_line().await?
                }
            },
            _ => unreachable!("unsupported MFA type was filtered out"),
        };

        let mut verify = Map::new();
        verify.insert("mfa_scene".to_string(), json!(VPN_MFA_SCENE));
        verify.insert("code_type".to_string(), json!(code_type));
        verify.insert("code".to_string(), json!(code));
        let verified = self
            .request::<Map<String, Value>>(ApiName::VpnMfaVerify, Some(verify))
            .await?;
        if verified.code != 0 {
            bail!(
                "failed to verify VPN MFA code with error {}: {}",
                verified.code,
                verified.message.unwrap_or_default()
            );
        }
        log::info!("VPN MFA verification succeeded");
        Ok(())
    }

    pub async fn connect_vpn(&mut self) -> Result<WgConf> {
        self.connect_vpn_inner().await
    }

    /// Refresh VPN configuration without prompting, sending MFA, or clearing
    /// authentication state. The caller classifies the typed terminal errors.
    pub async fn connect_vpn_for_recovery(&mut self) -> Result<WgConf> {
        self.automatic_recovery = true;
        let result = self.connect_vpn_inner().await;
        self.automatic_recovery = false;
        result
    }

    async fn connect_vpn_inner(&mut self) -> Result<WgConf> {
        self.initialize_session_setting().await?;
        let vpn_info = self.list_vpn().await?;
        if let Err(error) = self.start_vpn_push_websocket().await {
            log::warn!("FeiLian push WebSocket is unavailable: {error}");
        }

        log::info!(
            "found {} vpn(s), details: {:?}",
            vpn_info.len(),
            vpn_info
                .iter()
                .map(|i| {
                    if i.en_name.is_empty() {
                        i.name.clone()
                    } else {
                        i.en_name.clone()
                    }
                })
                .collect::<Vec<String>>()
        );
        let filtered_vpn = vpn_info
            .into_iter()
            .filter(|vpn| {
                if let Some(server_name) = self.conf.vpn_server_name.clone() {
                    if vpn.en_name != server_name {
                        log::info!(
                            "skip {}, expect {}",
                            if vpn.en_name.is_empty() {
                                &vpn.name
                            } else {
                                &vpn.en_name
                            },
                            server_name
                        );
                        return false;
                    }
                }
                true
            })
            .filter(|vpn| {
                let mode = match vpn.protocol_mode {
                    1 => "tcp",
                    2 => "udp",
                    _ => "unknown protocol",
                };
                match mode {
                    "udp" => true,
                    "tcp" => true,
                    _ => {
                        log::info!(
                            "server name {} is not support {} wg for now",
                            if vpn.en_name.is_empty() {
                                &vpn.name
                            } else {
                                &vpn.en_name
                            },
                            mode
                        );
                        false
                    }
                }
            })
            .collect();

        let vpn = match self.conf.vpn_select_strategy.clone() {
            Some(strategy) => match strategy.as_str() {
                STRATEGY_LATENCY => self.get_first_vpn_by_latency(filtered_vpn).await,
                STRATEGY_DEFAULT => self.get_first_available_vpn(filtered_vpn).await,
                _ => bail!("unsupported strategy"),
            },
            None => self.get_first_available_vpn(filtered_vpn).await,
        };

        let selected_vpn = vpn.context("no vpn available")?;
        let vpn = &selected_vpn.vpn;
        let endpoint_url = self.prepare_vpn_endpoint(&vpn.ip, vpn.api_port)?;
        // Persist only cookies returned by the selected endpoint probe.
        self.store_vpn_probe_cookies(&selected_vpn.set_cookie_headers, &endpoint_url)?;
        self.save_cookie()?;
        let vpn_addr = match vpn.ip.parse::<IpAddr>() {
            Ok(ip) => SocketAddr::new(ip, vpn.vpn_port).to_string(),
            Err(_) => format!("{}:{}", vpn.ip, vpn.vpn_port),
        };
        log::info!(
            "try connect to {}, address {}",
            if vpn.en_name.is_empty() {
                &vpn.name
            } else {
                &vpn.en_name
            },
            vpn_addr
        );

        log::info!("try to get wg conf from remote");
        let (wg_info, public_key, private_key) = self.fetch_peer_info().await?;
        let mtu = wg_info.setting.vpn_mtu;
        let primary_dns = wg_info.setting.vpn_dns;
        let backup_dns = wg_info.setting.vpn_dns_backup;
        let dns_domains = wg_info.setting.vpn_dns_domain_split.unwrap_or_default();
        let central_dns = wg_info.setting.central_dns;
        let mut dns_policy = NetstackDnsPolicy {
            split_domains: dns_domains.clone(),
            exact_v4: normalize_dns_records(wg_info.setting.dynamic_domain),
            exact_v6: normalize_dns_records(wg_info.setting.v6_vpn_dynamic_domain_route_split),
            wildcard_v4: normalize_dns_records(
                wg_info.setting.vpn_wildcard_dynamic_domain_route_split,
            ),
            suffix_v4: normalize_dns_records(
                wg_info.setting.suffix_wildcard_dynamic_domain_route_split,
            ),
            ..NetstackDnsPolicy::default()
        };
        merge_dns_records(
            &mut dns_policy.exact_v4,
            wg_info.setting.vpn_dynamic_domain_route_split,
        );
        let peer_key = wg_info.public_key;
        let ip_mask = wg_info.ip_mask.parse::<u32>().context("invalid ip mask")?;
        let address = format!("{}/{}", wg_info.ip, ip_mask);
        let has_ipv6_address = !wg_info.ipv6.is_empty();
        let address6 = has_ipv6_address
            .then_some(format!("{}/128", wg_info.ipv6))
            .unwrap_or_default();
        let mut allowed_ips = match self.conf.route_mode.clone().unwrap_or_default() {
            crate::config::RouteMode::Split => {
                log::info!("route_mode = split");
                let mut routes = wg_info.setting.vpn_route_split;
                let v6 = wg_info.setting.v6_route_split.unwrap_or_default();
                if has_ipv6_address {
                    routes.extend(v6);
                } else if !v6.is_empty() {
                    log::info!(
                        "ignoring {} IPv6 split routes because the server did not assign an IPv6 address",
                        v6.len()
                    );
                }
                routes
            }
            crate::config::RouteMode::Full => {
                log::info!("route_mode = full");
                let v4 = wg_info.setting.vpn_route_full;
                let v6 = wg_info.setting.v6_route_full.unwrap_or_default();
                log::info!(
                    "route_mode=full, server returned vpn_route_full ({} entries): {:?}",
                    v4.len(),
                    v4
                );
                log::info!(
                    "route_mode=full, server returned v6_route_full ({} entries): {:?}",
                    v6.len(),
                    v6
                );
                let mut routes = v4;
                if has_ipv6_address {
                    routes.extend(v6);
                } else if !v6.is_empty() {
                    log::info!(
                        "ignoring {} IPv6 full-tunnel routes because the server did not assign an IPv6 address",
                        v6.len()
                    );
                }
                if routes.is_empty() {
                    bail!(
                        "route_mode=full but server returned no usable routes; \
                         refuse to fall back to 0.0.0.0/0 to avoid peer-IP routing loop that blocks all traffic"
                    );
                }
                routes
            }
        };

        let netstack_mode = self.conf.socks5_listen.is_some();
        let netstack_dns = netstack_dns_config(
            &primary_dns,
            &backup_dns,
            central_dns.as_ref(),
            has_ipv6_address,
        );
        dns_policy.split_dns_servers = netstack_dns.split_servers.clone();
        let (dns, mut netstack_dns_routes) = if netstack_mode {
            if netstack_dns.servers.is_empty() {
                bail!("VPN server returned no usable DNS servers for SOCKS5/netstack mode");
            }
            log::info!(
                "SOCKS5/netstack DNS configured with {} server(s), {} split resolver(s), and {} dynamic record group(s)",
                netstack_dns.servers.split(',').count(),
                dns_policy.split_dns_servers.len(),
                dns_policy.exact_v4.len()
                    + dns_policy.exact_v6.len()
                    + dns_policy.wildcard_v4.len()
                    + dns_policy.suffix_v4.len()
            );
            if !dns_policy.split_domains.is_empty()
                && dns_policy.split_dns_servers.is_empty()
                && dns_policy.exact_v4.is_empty()
                && dns_policy.exact_v6.is_empty()
                && dns_policy.wildcard_v4.is_empty()
                && dns_policy.suffix_v4.is_empty()
            {
                log::warn!(
                    "VPN server provided internal DNS domains but no internal resolver or dynamic records; matching SOCKS5 queries will fail closed"
                );
            }
            (netstack_dns.servers, netstack_dns.routes)
        } else {
            (primary_dns, Vec::new())
        };
        if netstack_mode {
            netstack_dns_routes.extend(dynamic_dns_routes(&dns_policy, has_ipv6_address));
        }

        let mut additional_routes = self.conf.vpn_additional_routes.clone().unwrap_or_default();
        additional_routes.extend(netstack_dns_routes);
        if let Some(domains) = self.conf.vpn_additional_domains.as_deref() {
            additional_routes.extend(resolve_additional_domains(domains, has_ipv6_address).await);
        }
        if !additional_routes.is_empty() {
            let before = allowed_ips.len();
            allowed_ips =
                merge_additional_routes(allowed_ips, &additional_routes, has_ipv6_address);
            log::info!(
                "additional VPN routes merged: {} -> {} entries",
                before,
                allowed_ips.len()
            );
        }

        // Restrict server and user-added routes to the optional whitelist, then
        // carve out the optional denylist. A configured empty whitelist
        // intentionally yields no AllowedIPs/routes; invalid entries fail closed.
        if let Some(allowed) = self.conf.vpn_allowed_routes.as_deref() {
            for route in allowed {
                if !crate::utils::is_valid_cidr(route) {
                    log::warn!("ignoring invalid vpn_allowed_routes CIDR: {:?}", route);
                }
            }
        }
        let before = allowed_ips.len();
        allowed_ips = crate::utils::apply_route_filters(
            &allowed_ips,
            self.conf.vpn_allowed_routes.as_deref(),
            self.conf.vpn_disallowed_routes.as_deref(),
        );
        if self.conf.vpn_allowed_routes.is_some() || self.conf.vpn_disallowed_routes.is_some() {
            log::info!(
                "VPN route filters applied: {} -> {} entries",
                before,
                allowed_ips.len()
            );
        }

        // Auto-carve the VPN peer endpoint IP out of allowed_ips. In full-tunnel mode
        // the server typically returns 0.0.0.0/0, which would match the outer UDP
        // packets going to the peer itself, producing a routing loop (black hole).
        // Mirrors wg-quick's behavior of excluding the endpoint from routes. No-op
        // when the peer IP isn't covered by any allowed_ip (e.g. split mode).
        match vpn.ip.parse::<std::net::IpAddr>() {
            Ok(peer_ip) => {
                let peer_cidr = match peer_ip {
                    std::net::IpAddr::V4(_) => format!("{}/32", peer_ip),
                    std::net::IpAddr::V6(_) => format!("{}/128", peer_ip),
                };
                let before = allowed_ips.len();
                let mut carved = Vec::with_capacity(allowed_ips.len());
                for a in &allowed_ips {
                    carved.extend(crate::utils::subtract_cidr_from_cidr(a, &peer_cidr));
                }
                if carved.len() != before {
                    log::info!(
                        "auto-carved peer endpoint {} out of allowed_ips: {} -> {} entries",
                        peer_cidr,
                        before,
                        carved.len()
                    );
                }
                allowed_ips = carved;
            }
            Err(e) => {
                log::warn!(
                    "could not parse vpn.ip {:?} as IP, skipping peer-IP carve-out: {}",
                    vpn.ip,
                    e
                );
            }
        }
        log::info!("final allowed_ips: {} entries", allowed_ips.len());
        log::debug!("final allowed_ips: {:?}", allowed_ips);
        let auto_setup_routes = self.conf.auto_setup_routes.unwrap_or(true);
        let routes = if auto_setup_routes {
            allowed_ips.clone()
        } else {
            log::info!("auto_setup_routes is disabled, skip setting routes");
            Vec::new()
        };

        // corplink config
        let wg_conf = WgConf {
            address,
            address6,
            peer_address: vpn_addr,
            mtu,
            public_key,
            private_key,
            peer_key,
            allowed_ips,
            routes,
            dns,
            dns_domains,
            dns_policy,
            // `force_protocol`, when set, overrides the server-advertised `protocol_mode`
            protocol: match self.conf.force_protocol.as_deref() {
                Some(p) if p.eq_ignore_ascii_case("udp") => 0,
                Some(p) if p.eq_ignore_ascii_case("tcp") => 1,
                _ => match vpn.protocol_mode {
                    // tcp
                    1 => 1,
                    // udp
                    _ => 0,
                },
            },
        };
        Ok(wg_conf)
    }

    pub async fn keep_alive_vpn(&mut self, conf: &WgConf, interval: u64) {
        loop {
            log::info!("keep alive");
            match self.report_vpn_status(conf).await {
                Ok(_) => (),
                Err(err) => {
                    log::warn!("keep alive error: {}", err);
                    return;
                }
            }
            tokio::time::sleep(Duration::from_secs(interval)).await;
        }
    }

    pub async fn report_vpn_status(&mut self, conf: &WgConf) -> Result<()> {
        let mut m = Map::new();
        m.insert("ip".to_string(), json!(conf.address));
        m.insert("public_key".to_string(), json!(conf.public_key));
        m.insert(
            "mode".to_string(),
            json!(match self.conf.route_mode.clone().unwrap_or_default() {
                crate::config::RouteMode::Split => "Split",
                crate::config::RouteMode::Full => "Full",
            }),
        );
        m.insert("type".to_string(), json!("100"));

        let resp = self
            .request::<Map<String, Value>>(ApiName::KeepAliveVPN, Some(m))
            .await?;
        match resp.code {
            0 => Ok(()),
            _ => bail!(format!(
                "failed to report connection with error {}: {}",
                resp.code,
                resp.message.unwrap_or_default()
            )),
        }
    }

    pub async fn disconnect_vpn(&mut self, wg_conf: &WgConf) -> Result<()> {
        let mut m = Map::new();
        m.insert("ip".to_string(), json!(wg_conf.address));
        m.insert("public_key".to_string(), json!(wg_conf.public_key));
        m.insert(
            "mode".to_string(),
            json!(match self.conf.route_mode.clone().unwrap_or_default() {
                crate::config::RouteMode::Split => "Split",
                crate::config::RouteMode::Full => "Full",
            }),
        );
        m.insert("type".to_string(), json!("101"));
        let resp = self
            .request::<Map<String, Value>>(ApiName::DisconnectVPN, Some(m))
            .await?;
        match resp.code {
            0 => Ok(()),
            _ => bail!(format!(
                "failed to fetch peer info with error {}: {}",
                resp.code,
                resp.message.unwrap_or_default()
            )),
        }
    }

    // log out the current terminal, freeing its server-side session/terminal
    // quota (servers cap concurrent terminals, e.g. nankai allows only 3).
    // best-effort: callers treat failures as non-fatal since we're exiting.
    pub async fn logout(&mut self) -> Result<()> {
        let url = self
            .api_url
            .get_api_url_with_offset(&ApiName::Logout, self.date_offset_sec);
        let parsed_url = Url::parse(&url).context("invalid logout URL")?;
        let mut req = self.c.get(url);
        if let Some(cookies) = self.cookie_header_for_url(&parsed_url)? {
            req = req.header(header::COOKIE, cookies);
        }
        // /api/logout validates a csrf-token header (double-submit against the
        // cookie). the token is only known after login, so read it from the
        // cookie store here rather than relying on the default headers.
        if let Some(server) = self.conf.server.as_ref() {
            if let Ok(server_url) = Url::parse(server) {
                if let Some(domain) = server_url.domain().or_else(|| server_url.host_str()) {
                    let token = {
                        let store = self
                            .cookie
                            .lock()
                            .map_err(|e| anyhow!("failed to lock cookie store: {e}"))?;
                        store
                            .get(domain, "/", "csrf-token")
                            .map(|c| c.value().to_string())
                    };
                    if let Some(token) = token {
                        if let Ok(value) = header::HeaderValue::from_str(&token) {
                            req = req.header("csrf-token", value);
                        }
                    }
                }
            }
        }
        // the endpoint replies with a 302 redirect (not JSON), so just confirm
        // the request went through instead of parsing a response body.
        let resp = req.send().await.context("logout request failed")?;
        log::info!("logout (current terminal) status: {}", resp.status());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use cookie::Cookie as RawCookie;
    use cookie_store::CookieStore;
    use futures::{SinkExt, StreamExt};
    use reqwest::{header, Url};
    use reqwest_cookie_store::CookieStoreMutex;
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::{broadcast, oneshot, Barrier};
    use tokio::time::{sleep, timeout};

    use super::{
        dynamic_dns_routes, encode_sign_header, hkdf_sha256, merge_additional_routes,
        netstack_dns_config, normalize_mac_address, parse_websocket_event, pump_vpn_push_websocket,
        resolve_additional_domains, select_supported_vpn_mfa_type, value_after_keyword,
        vpn_connect_body, vpn_push_result, wait_for_vpn_push_confirmation, websocket_header,
        Client, ReqwestCookieStore, VpnPushConnector, WebSocketEvent,
    };
    use crate::api::{ApiName, ApiUrl};
    use crate::config::{Config, NetstackDnsPolicy, RouteMode};
    use crate::resp::{RespCentralDns, RespVpnInfo, RespVpnMfaType};
    use crate::utils::apply_route_filters;

    #[test]
    fn hkdf_sha256_matches_rfc5869_case_1() {
        let ikm = vec![0x0b; 22];
        let salt = hex::decode("000102030405060708090a0b0c").unwrap();
        let info = hex::decode("f0f1f2f3f4f5f6f7f8f9").unwrap();
        let okm = hkdf_sha256(&ikm, &salt, &info, 42);
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a\
             2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
             34007208d5b887185865"
                .replace(char::is_whitespace, "")
        );
    }

    #[test]
    fn sign_header_uses_observed_wire_shape() {
        let header = encode_sign_header(510, &[0x11; 32]);
        assert!(header.starts_with("v1;"));
        let encoded = header.trim_start_matches("v1;");
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .unwrap();
        assert_eq!(
            hex::encode(bytes),
            format!("080118fe032220{}", "11".repeat(32))
        );
    }

    #[test]
    fn vpn_mfa_selection_uses_server_order() {
        let methods = RespVpnMfaType {
            vpn_types: vec!["push".to_string(), "email".to_string(), "otp".to_string()],
            types: vec!["mobile".to_string()],
        };

        assert_eq!(select_supported_vpn_mfa_type(&methods, None), Some("push"));
    }

    #[test]
    fn vpn_mfa_selection_falls_back_to_general_types() {
        let methods = RespVpnMfaType {
            vpn_types: Vec::new(),
            types: vec!["otp".to_string()],
        };

        assert_eq!(select_supported_vpn_mfa_type(&methods, None), Some("otp"));
    }

    #[test]
    fn vpn_mfa_selection_honors_an_available_preference() {
        let methods = RespVpnMfaType {
            vpn_types: vec!["otp".to_string(), "email".to_string()],
            types: Vec::new(),
        };

        assert_eq!(
            select_supported_vpn_mfa_type(&methods, Some("email")),
            Some("email")
        );
    }

    #[test]
    fn vpn_mfa_selection_honors_push_preference() {
        let methods = RespVpnMfaType {
            vpn_types: vec!["otp".to_string(), "push".to_string()],
            types: Vec::new(),
        };

        assert_eq!(
            select_supported_vpn_mfa_type(&methods, Some("push")),
            Some("push")
        );
    }

    #[test]
    fn vpn_connect_body_matches_official_fields() {
        let body = vpn_connect_body("wg-public-key", "", &RouteMode::Split, "00:11:22:33:44:55");

        assert_eq!(body.get("mode"), Some(&json!("Split")));
        assert_eq!(body.get("not_auto"), Some(&json!(true)));
        assert_eq!(body.get("export_id"), Some(&json!(0)));
        assert_eq!(body.get("public_key"), Some(&json!("wg-public-key")));
        assert_eq!(body.get("smac"), Some(&json!("00:11:22:33:44:55")));
        assert!(!body.contains_key("otp"));

        let body = vpn_connect_body(
            "wg-public-key",
            "123456",
            &RouteMode::Full,
            "00:11:22:33:44:55",
        );
        assert_eq!(body.get("mode"), Some(&json!("Full")));
        assert_eq!(body.get("otp"), Some(&json!("123456")));
    }

    #[test]
    fn vpn_push_event_requires_matching_message_id() {
        let event = json!({
            "tenantID": "tenant",
            "id": "event-id",
            "action": "push_mfa",
            "data": json!({
                "check_result": "confirm",
                "message_id": "expected",
                "scene": "vpn",
                "type": "mfa"
            }).to_string(),
            "send_time": 1
        });

        let event = parse_websocket_event(&event.to_string()).unwrap();
        assert_eq!(
            event,
            WebSocketEvent {
                event_id: "event-id".to_string(),
                action: "push_mfa".to_string(),
                data: Some(json!({
                    "check_result": "confirm",
                    "message_id": "expected",
                    "scene": "vpn",
                    "type": "mfa"
                })),
            }
        );
        assert_eq!(vpn_push_result(&event, "expected"), Some(true));
        assert_eq!(vpn_push_result(&event, "other"), None);
    }

    #[test]
    fn default_interface_output_parsers_are_strict() {
        let route = "gateway: 192.0.2.1\n  interface: en0\n";
        assert_eq!(
            value_after_keyword(route, "interface").as_deref(),
            Some("en0")
        );
        assert_eq!(
            normalize_mac_address("AA-BB-CC-DD-EE-FF").as_deref(),
            Some("aa:bb:cc:dd:ee:ff")
        );
        assert_eq!(normalize_mac_address("not-a-mac"), None);
    }

    #[tokio::test]
    async fn vpn_push_confirmation_acknowledges_matching_event() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut websocket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let unrelated = json!({
                "tenantID": "tenant",
                "id": "unrelated-event",
                "action": "config_update",
                "data": "{}",
                "send_time": 1
            });
            websocket
                .send(tokio_tungstenite::tungstenite::Message::Text(
                    unrelated.to_string(),
                ))
                .await
                .unwrap();
            let unrelated_ack = websocket.next().await.unwrap().unwrap();
            let event = json!({
                "tenantID": "tenant",
                "id": "event-id",
                "action": "push_mfa",
                "data": json!({
                    "check_result": "confirm",
                    "message_id": "expected",
                    "scene": "vpn",
                    "type": "mfa"
                }).to_string(),
                "send_time": 1
            });
            websocket
                .send(tokio_tungstenite::tungstenite::Message::Binary(
                    event.to_string().into_bytes(),
                ))
                .await
                .unwrap();
            let matching_ack = websocket.next().await.unwrap().unwrap();
            (unrelated_ack, matching_ack)
        });

        let (mut websocket, _) = tokio_tungstenite::connect_async(format!("ws://{address}"))
            .await
            .unwrap();
        let (events, _) = broadcast::channel(8);
        let mut receiver = events.subscribe();
        let pump = tokio::spawn(async move {
            let mut received_ids = HashSet::new();
            pump_vpn_push_websocket(&mut websocket, &events, &mut received_ids).await
        });
        assert!(
            wait_for_vpn_push_confirmation(&mut receiver, "expected", Duration::from_secs(2))
                .await
                .unwrap()
        );

        let (unrelated_ack, matching_ack) = server.await.unwrap();
        pump.abort();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&unrelated_ack.into_text().unwrap()).unwrap(),
            json!({
                "id": "unrelated-event",
                "action": "message_received",
                "data": ""
            })
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&matching_ack.into_text().unwrap()).unwrap(),
            json!({
                "id": "event-id",
                "action": "message_received",
                "data": ""
            })
        );
    }

    #[tokio::test]
    async fn vpn_push_confirmation_reports_timeout() {
        let (events, _) = broadcast::channel(1);
        let mut receiver = events.subscribe();

        assert!(!wait_for_vpn_push_confirmation(
            &mut receiver,
            "expected",
            Duration::from_millis(1),
        )
        .await
        .unwrap());
    }

    async fn start_probe_server(
        barrier: Arc<Barrier>,
        response_delay: Duration,
        session: &'static str,
    ) -> (u16, oneshot::Receiver<String>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (request_tx, request_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let count = stream.read(&mut buffer).await.unwrap();
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..count]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            request_tx
                .send(String::from_utf8(request).unwrap())
                .unwrap();

            barrier.wait().await;
            sleep(response_delay).await;
            let body = r#"{"code":0}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nSet-Cookie: vpn_session={session}; Path=/\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        (port, request_rx, task)
    }

    fn vpn_info(port: u16, name: &str) -> RespVpnInfo {
        RespVpnInfo {
            api_port: port,
            vpn_port: port,
            ip: "127.0.0.1".to_string(),
            protocol_mode: 2,
            name: name.to_string(),
            en_name: name.to_string(),
            icon: String::new(),
            id: 0,
            timeout: 0,
        }
    }

    fn test_client() -> Client {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let mut conf: Config = serde_json::from_value(json!({
            "company_name": "test",
            "username": "test",
            "server": "http://127.0.0.1",
            "interface_name": format!("corplink-probe-test-{unique}"),
            "device_id": "test-device",
            "device_name": "Test Mac"
        }))
        .unwrap();
        conf.conf_file = Some(
            std::env::temp_dir()
                .join(format!("corplink-probe-test-{unique}.json"))
                .to_string_lossy()
                .into_owned(),
        );
        Client::new(conf).unwrap()
    }

    #[test]
    fn dedicated_feilian_platforms_follow_only_the_feilian_login_order() {
        let mut client = test_client();
        for platform in [
            crate::config::PLATFORM_CORPLINK_EMAIL,
            crate::config::PLATFORM_CORPLINK_QR,
        ] {
            client.conf.platform = Some(platform.to_string());

            assert!(client.is_platform_or_default(crate::config::PLATFORM_CORPLINK));
            assert!(!client.is_platform_or_default(crate::config::PLATFORM_LDAP));
            assert!(!client.is_platform_or_default(crate::config::PLATFORM_LARK));
        }
    }

    #[test]
    fn vpn_push_websocket_request_matches_official_headers() {
        let conf: Config = serde_json::from_value(json!({
            "company_name": "test",
            "username": "test",
            "server": "https://vpn.example.com:10443",
            "device_id": "test-device",
            "device_name": "Test Mac"
        }))
        .unwrap();
        let server_url = Url::parse(conf.server.as_deref().unwrap()).unwrap();
        let mut store = CookieStore::default();
        store
            .insert_raw(&RawCookie::new("session", "test-session"), &server_url)
            .unwrap();
        let connector = VpnPushConnector {
            api_url: ApiUrl::new(&conf).unwrap(),
            cookie: Arc::new(CookieStoreMutex::new(store)),
            server_url,
            server_time_offset_sec: 0,
            device_cookie_header: Client::websocket_device_cookie_header_for_config(&conf).unwrap(),
        };

        let request = connector.build_request().unwrap();
        assert_eq!(
            request.headers()[websocket_header::USER_AGENT],
            "Go-http-client/1.1"
        );
        assert_eq!(
            request.headers()[websocket_header::ORIGIN],
            "https://vpn.example.com:10443"
        );
        assert!(request.headers()[websocket_header::COOKIE]
            .to_str()
            .unwrap()
            .starts_with(
                "device_id=test-device; HttpOnly; Secure; device_name=Test+Mac; HttpOnly; Secure; session=test-session"
            ));
    }

    #[test]
    fn vpn_probe_cookies_follow_standard_secure_cookie_scope() {
        let client = test_client();
        let endpoint = Url::parse("http://192.0.2.1:80").unwrap();
        let headers = vec![header::HeaderValue::from_static(
            "vpn-token=test-token; Secure; HttpOnly; Path=/",
        )];

        client.store_vpn_probe_cookies(&headers, &endpoint).unwrap();

        let header = client.cookie_header_for_url(&endpoint).unwrap().unwrap();
        let header = header.to_str().unwrap();
        assert!(header.starts_with("device_id=test-device; device_name=Test+Mac"));
        assert!(!header.contains("vpn-token=test-token"));
    }

    #[test]
    fn connect_request_forwards_login_cookies_to_vpn_endpoint() {
        let client = test_client();
        let server = Url::parse("http://127.0.0.1").unwrap();
        let endpoint = Url::parse("http://192.0.2.1:80/vpn/conn").unwrap();
        {
            let mut cookies = client.cookie.lock().unwrap();
            cookies
                .insert_raw(&RawCookie::new("session", "login-session"), &server)
                .unwrap();
            cookies
                .insert_raw(&RawCookie::new("vpn-token", "endpoint-token"), &endpoint)
                .unwrap();
        }

        let header = client
            .cookie_header_for_request(&ApiName::ConnectVPN, &endpoint)
            .unwrap()
            .unwrap();
        let header = header.to_str().unwrap();

        assert!(header.starts_with("device_id=test-device; device_name=Test+Mac; "));
        assert!(header.contains("session=login-session"));
        assert!(header.contains("vpn-token=endpoint-token"));
    }

    #[test]
    fn connect_request_without_vpn_token_still_uses_official_signing_shape() {
        let client = test_client();
        let endpoint = Url::parse("http://192.0.2.1/vpn/conn?os=Android&os_version=2").unwrap();

        let signature = client
            .sign_request(
                &ApiName::ConnectVPN,
                "POST",
                &endpoint,
                Some(r#"{"public_key":"test","otp":""}"#),
                None,
                None,
                None,
            )
            .unwrap();

        assert!(signature.is_some_and(|value| value.starts_with("v1;")));
    }

    #[test]
    fn vpn_token_is_used_as_jwt_header_and_connect_signature_input() {
        let client = test_client();
        let server = Url::parse("http://127.0.0.1").unwrap();
        let endpoint = Url::parse("http://192.0.2.1/vpn/conn?os=Android&os_version=2").unwrap();
        client
            .cookie
            .lock()
            .unwrap()
            .insert_raw(&RawCookie::new("vpn-token", "test-token"), &server)
            .unwrap();

        let jwt_token = client
            .jwt_token_for_request(&ApiName::ConnectVPN)
            .unwrap()
            .unwrap();
        assert_eq!(jwt_token, "test-token");

        let signature = client
            .sign_request(
                &ApiName::ConnectVPN,
                "POST",
                &endpoint,
                Some(r#"{"public_key":"test","otp":""}"#),
                None,
                None,
                Some(&jwt_token),
            )
            .unwrap();

        assert!(signature.is_some_and(|value| value.starts_with("v1;")));
    }

    #[tokio::test]
    async fn concurrent_default_probe_preserves_order_and_isolates_cookie_state() {
        let barrier = Arc::new(Barrier::new(3));
        let (first_port, first_request, first_task) =
            start_probe_server(Arc::clone(&barrier), Duration::from_millis(75), "first").await;
        let (second_port, second_request, second_task) =
            start_probe_server(Arc::clone(&barrier), Duration::ZERO, "second").await;

        let client = test_client();
        let candidates = vec![
            vpn_info(first_port, "first"),
            vpn_info(second_port, "second"),
        ];

        let selected = timeout(Duration::from_secs(5), async {
            let (selected, _) =
                tokio::join!(client.get_first_available_vpn(candidates), barrier.wait());
            selected
        })
        .await
        .expect("VPN probes did not run concurrently")
        .expect("no VPN was selected");

        assert_eq!(selected.vpn.en_name, "first");
        assert!(selected.set_cookie_headers[0]
            .to_str()
            .unwrap()
            .starts_with("vpn_session=first"));
        let first_request = first_request.await.unwrap().to_ascii_lowercase();
        let second_request = second_request.await.unwrap().to_ascii_lowercase();
        assert!(first_request.contains("cookie: device_id=test-device"));
        assert!(second_request.contains("cookie: device_id=test-device"));
        assert!(first_request.contains("user-agent: corplink/3.2.16 "));
        assert!(second_request.contains("user-agent: corplink/3.2.16 "));

        {
            let cookie_store = client.cookie.lock().unwrap();
            assert!(cookie_store.get("127.0.0.1", "/", "vpn_session").is_none());
        }
        let endpoint_url = client
            .vpn_endpoint_url(&selected.vpn.ip, selected.vpn.api_port)
            .unwrap();
        ReqwestCookieStore::set_cookies(
            client.cookie.as_ref(),
            &mut selected.set_cookie_headers.iter(),
            &endpoint_url,
        );
        {
            let cookie_store = client.cookie.lock().unwrap();
            assert_eq!(
                cookie_store
                    .get("127.0.0.1", "/", "vpn_session")
                    .unwrap()
                    .value(),
                "first"
            );
        }

        first_task.await.unwrap();
        second_task.await.unwrap();
    }

    #[tokio::test]
    async fn concurrent_latency_probe_selects_the_fastest_endpoint() {
        let barrier = Arc::new(Barrier::new(3));
        let (slow_port, slow_request, slow_task) =
            start_probe_server(Arc::clone(&barrier), Duration::from_millis(75), "slow").await;
        let (fast_port, fast_request, fast_task) =
            start_probe_server(Arc::clone(&barrier), Duration::ZERO, "fast").await;
        let client = test_client();
        let candidates = vec![vpn_info(slow_port, "slow"), vpn_info(fast_port, "fast")];

        let selected = timeout(Duration::from_secs(5), async {
            let (selected, _) =
                tokio::join!(client.get_first_vpn_by_latency(candidates), barrier.wait());
            selected
        })
        .await
        .expect("VPN probes did not run concurrently")
        .expect("no VPN was selected");

        assert_eq!(selected.vpn.en_name, "fast");
        assert!(selected.set_cookie_headers[0]
            .to_str()
            .unwrap()
            .starts_with("vpn_session=fast"));
        slow_request.await.unwrap();
        fast_request.await.unwrap();
        slow_task.await.unwrap();
        fast_task.await.unwrap();
    }

    #[test]
    fn vpn_endpoint_urls_use_server_scheme_and_candidate_host() {
        let mut client = test_client();
        client.conf.server = Some("https://127.0.0.1/base?source=config#fragment".to_string());

        let hostname_endpoint = client
            .vpn_endpoint_url("vpn-node.example.com", 8443)
            .unwrap();
        let ipv4_endpoint = client.vpn_endpoint_url("192.0.2.1", 8443).unwrap();
        let ipv6_endpoint = client.prepare_vpn_endpoint("2001:db8::1", 8443).unwrap();
        let ipv6_cookies = ReqwestCookieStore::cookies(client.cookie.as_ref(), &ipv6_endpoint);
        let tenant_cookies = client
            .tenant_cookie_header()
            .unwrap()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        assert_eq!(
            hostname_endpoint.as_str(),
            "https://vpn-node.example.com:8443/"
        );
        assert_eq!(ipv4_endpoint.as_str(), "https://192.0.2.1:8443/");
        assert_eq!(ipv6_endpoint.as_str(), "https://[2001:db8::1]:8443/");
        assert!(ipv6_cookies.is_none());
        assert!(tenant_cookies.contains("device_id=test-device"));
    }

    #[test]
    fn additional_routes_are_validated_deduplicated_and_merged() {
        let routes = merge_additional_routes(
            vec!["10.0.0.0/8".to_string()],
            &[
                "10.0.0.0/8".to_string(),
                "20.205.243.160/28".to_string(),
                "invalid".to_string(),
                "2001:db8::/32".to_string(),
            ],
            false,
        );

        assert_eq!(routes, vec!["10.0.0.0/8", "20.205.243.160/28"]);
    }

    #[test]
    fn additional_ipv6_routes_are_kept_with_an_ipv6_address() {
        let routes = merge_additional_routes(Vec::new(), &["2001:db8::/32".to_string()], true);

        assert_eq!(routes, vec!["2001:db8::/32"]);
    }

    #[test]
    fn netstack_dns_uses_primary_and_backup_with_host_routes() {
        let config = netstack_dns_config("8.8.8.8", "10.20.0.53", None, false);

        assert_eq!(config.servers, "8.8.8.8,10.20.0.53");
        assert_eq!(config.split_servers, vec!["8.8.8.8", "10.20.0.53"]);
        assert_eq!(config.routes, vec!["8.8.8.8/32", "10.20.0.53/32"]);
    }

    #[test]
    fn netstack_dns_deduplicates_and_skips_unusable_ipv6() {
        let config = netstack_dns_config("8.8.8.8,2001:4860:4860::8888", "8.8.8.8", None, false);

        assert_eq!(config.servers, "8.8.8.8");
        assert_eq!(config.split_servers, vec!["8.8.8.8"]);
        assert_eq!(config.routes, vec!["8.8.8.8/32"]);
    }

    #[test]
    fn central_dns_is_preferred_for_split_domains() {
        let central = RespCentralDns {
            dnat_ip: "100.64.0.53".to_string(),
        };
        let config = netstack_dns_config("8.8.8.8", "", Some(&central), false);

        assert_eq!(config.split_servers, vec!["100.64.0.53", "8.8.8.8"]);
        assert_eq!(config.routes, vec!["8.8.8.8/32", "100.64.0.53/32"]);
    }

    #[test]
    fn server_supplied_public_central_dns_is_used_for_split_domains() {
        let central = RespCentralDns {
            dnat_ip: "1.1.1.1".to_string(),
        };
        let config = netstack_dns_config("8.8.8.8", "", Some(&central), false);

        assert_eq!(config.split_servers, vec!["1.1.1.1", "8.8.8.8"]);
        assert_eq!(config.routes, vec!["8.8.8.8/32", "1.1.1.1/32"]);
    }

    #[test]
    fn dynamic_dns_addresses_add_tunnel_host_routes() {
        let mut policy = NetstackDnsPolicy::default();
        policy.exact_v4.insert(
            "internal.example.com".to_string(),
            vec!["10.0.0.10/24".to_string()],
        );
        policy.exact_v6.insert(
            "v6.internal.example.com".to_string(),
            vec!["fd00::10/128".to_string()],
        );

        assert_eq!(dynamic_dns_routes(&policy, false), vec!["10.0.0.10/32"]);
        assert_eq!(
            dynamic_dns_routes(&policy, true),
            vec!["10.0.0.10/32", "fd00::10/128"]
        );
    }

    #[test]
    fn additional_routes_are_merged_before_route_filters() {
        let routes = merge_additional_routes(
            vec!["10.0.0.0/8".to_string()],
            &["20.205.243.160/28".to_string()],
            false,
        );
        let allowed = ["20.205.243.160/28".to_string()];

        assert_eq!(
            apply_route_filters(&routes, Some(&allowed), None),
            vec!["20.205.243.160/28"]
        );
    }

    #[tokio::test]
    async fn additional_domains_are_resolved_to_host_routes() {
        let routes = resolve_additional_domains(&["127.0.0.1".to_string()], false).await;

        assert_eq!(routes, vec!["127.0.0.1/32"]);
    }
}
