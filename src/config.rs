use std::env;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;
use tokio::fs;

use anyhow::{bail, Context, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::state::State;
use crate::utils;

#[cfg(target_os = "macos")]
const DEFAULT_INTERFACE_NAME: &str = "utun12345";
#[cfg(not(target_os = "macos"))]
const DEFAULT_INTERFACE_NAME: &str = "corplink";
pub const DEFAULT_CONFIG_FILE_NAME: &str = "feilian-cli.config.json";

pub const DEFAULT_HEALTH_INTERVAL_SECONDS: u64 = 60;
pub const DEFAULT_HEALTH_INITIAL_DELAY_SECONDS: u64 = 15;
pub const DEFAULT_HEALTH_DNS_TIMEOUT_SECONDS: u64 = 5;
pub const DEFAULT_HEALTH_REQUEST_TIMEOUT_SECONDS: u64 = 10;
pub const DEFAULT_HEALTH_FAILURE_THRESHOLD: u32 = 3;
pub const DEFAULT_HEALTH_RECOVERY_COOLDOWN_SECONDS: u64 = 60;
pub const DEFAULT_HEALTH_MAX_RECOVERY_ATTEMPTS: u32 = 3;

pub const PLATFORM_LDAP: &str = "ldap";
pub const PLATFORM_CORPLINK: &str = "feilian";
// Email verification login for newer feilian deployments where /api/lookup is
// unavailable. It follows the server's "feilian" login order but skips the
// per-user lookup and goes directly through code send/verify.
pub const PLATFORM_CORPLINK_EMAIL: &str = "feilian_email";
// QR-code login through the current feilian /api/login/token flow.
pub const PLATFORM_CORPLINK_QR: &str = "feilian_qr";
// new feilian login that uses the v1 API (/api/v1/login with an AES-encrypted
// password), as served by the newer feilian backend. opt-in via config.
pub const PLATFORM_CORPLINK_V1: &str = "feilian_v1";
pub const PLATFORM_OIDC: &str = "OIDC";
// aka feishu
pub const PLATFORM_LARK: &str = "lark";
#[allow(dead_code)]
pub const PLATFORM_WEIXIN: &str = "weixin";
// aka dingding
#[allow(dead_code)]
pub const PLATFORM_DING_TALK: &str = "dingtalk";
// unknown
#[allow(dead_code)]
pub const PLATFORM_AAD: &str = "aad";

pub const STRATEGY_LATENCY: &str = "latency";
pub const STRATEGY_DEFAULT: &str = "default";

fn generate_device_id() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn official_device_name() -> String {
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = Command::new("/usr/sbin/scutil")
            .args(["--get", "ComputerName"])
            .output()
        {
            if output.status.success() {
                let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !name.is_empty() {
                    return name;
                }
            }
        }
    }

    env::var("HOSTNAME")
        .ok()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| "CorpLink".to_string())
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum RouteMode {
    /// Only intranet routes returned by the server (mimics official split mode).
    #[default]
    Split,
    /// Full-tunnel routes from the server (typically 0.0.0.0/0, ::/0).
    Full,
}

impl fmt::Display for RouteMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            RouteMode::Split => write!(f, "split"),
            RouteMode::Full => write!(f, "full"),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HealthCheckTarget {
    pub url: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HealthCheckConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Optional compatibility fallback. Server-provided VPN DNS domains are
    /// preferred when they contain a usable health-check candidate.
    #[serde(default)]
    pub targets: Vec<HealthCheckTarget>,
    #[serde(default = "default_health_interval_seconds")]
    pub interval_seconds: u64,
    #[serde(default = "default_health_initial_delay_seconds")]
    pub initial_delay_seconds: u64,
    #[serde(default = "default_health_dns_timeout_seconds")]
    pub dns_timeout_seconds: u64,
    #[serde(default = "default_health_request_timeout_seconds")]
    pub request_timeout_seconds: u64,
    #[serde(default = "default_health_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_health_recovery_cooldown_seconds")]
    pub recovery_cooldown_seconds: u64,
    #[serde(default = "default_health_max_recovery_attempts")]
    pub max_recovery_attempts: u32,
}

const fn default_health_interval_seconds() -> u64 {
    DEFAULT_HEALTH_INTERVAL_SECONDS
}

const fn default_health_initial_delay_seconds() -> u64 {
    DEFAULT_HEALTH_INITIAL_DELAY_SECONDS
}

const fn default_health_dns_timeout_seconds() -> u64 {
    DEFAULT_HEALTH_DNS_TIMEOUT_SECONDS
}

const fn default_health_request_timeout_seconds() -> u64 {
    DEFAULT_HEALTH_REQUEST_TIMEOUT_SECONDS
}

const fn default_health_failure_threshold() -> u32 {
    DEFAULT_HEALTH_FAILURE_THRESHOLD
}

const fn default_health_recovery_cooldown_seconds() -> u64 {
    DEFAULT_HEALTH_RECOVERY_COOLDOWN_SECONDS
}

const fn default_health_max_recovery_attempts() -> u32 {
    DEFAULT_HEALTH_MAX_RECOVERY_ATTEMPTS
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            targets: Vec::new(),
            interval_seconds: DEFAULT_HEALTH_INTERVAL_SECONDS,
            initial_delay_seconds: DEFAULT_HEALTH_INITIAL_DELAY_SECONDS,
            dns_timeout_seconds: DEFAULT_HEALTH_DNS_TIMEOUT_SECONDS,
            request_timeout_seconds: DEFAULT_HEALTH_REQUEST_TIMEOUT_SECONDS,
            failure_threshold: DEFAULT_HEALTH_FAILURE_THRESHOLD,
            recovery_cooldown_seconds: DEFAULT_HEALTH_RECOVERY_COOLDOWN_SECONDS,
            max_recovery_attempts: DEFAULT_HEALTH_MAX_RECOVERY_ATTEMPTS,
        }
    }
}

impl HealthCheckConfig {
    fn validate(&self) -> Result<()> {
        if self.interval_seconds == 0 {
            bail!("health_check.interval_seconds must be greater than zero");
        }
        if self.dns_timeout_seconds == 0 {
            bail!("health_check.dns_timeout_seconds must be greater than zero");
        }
        if self.request_timeout_seconds == 0 {
            bail!("health_check.request_timeout_seconds must be greater than zero");
        }
        if self.failure_threshold == 0 {
            bail!("health_check.failure_threshold must be greater than zero");
        }
        if self.recovery_cooldown_seconds == 0 {
            bail!("health_check.recovery_cooldown_seconds must be greater than zero");
        }
        if self.max_recovery_attempts == 0 {
            bail!("health_check.max_recovery_attempts must be greater than zero");
        }
        for (index, target) in self.targets.iter().enumerate() {
            let url = reqwest::Url::parse(&target.url)
                .with_context(|| format!("health_check.targets[{index}].url is invalid"))?;
            if !matches!(url.scheme(), "http" | "https") {
                bail!("health_check.targets[{index}].url must use http or https");
            }
            if url.host_str().is_none() {
                bail!("health_check.targets[{index}].url must include a host");
            }
            if !url.username().is_empty() || url.password().is_some() {
                bail!("health_check.targets[{index}].url must not include credentials");
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Config {
    pub company_name: String,
    pub username: String,
    pub password: Option<String>,
    pub platform: Option<String>,
    pub code: Option<String>,
    pub device_name: Option<String>,
    pub device_id: Option<String>,
    pub public_key: Option<String>,
    pub private_key: Option<String>,
    pub server: Option<String>,
    pub interface_name: Option<String>,
    pub debug_wg: Option<bool>,
    #[serde(skip_serializing)]
    pub conf_file: Option<String>,
    pub state: Option<State>,
    pub vpn_server_name: Option<String>,
    pub vpn_select_strategy: Option<String>,
    /// Preferred VPN MFA method: "push", "email", "mobile", or "otp". When omitted or
    /// unavailable, the first supported method returned by the server is used.
    pub vpn_mfa_type: Option<String>,
    pub use_vpn_dns: Option<bool>,
    pub dns_backup_filename: Option<String>,
    pub auto_setup_routes: Option<bool>,
    /// "split" (default) or "full". Selects which route list from the server to apply.
    pub route_mode: Option<RouteMode>,
    /// Optional CIDRs added to the server-provided routes before route filters.
    /// Unlike `vpn_allowed_routes`, this expands the route set. The combined routes
    /// are then restricted by `vpn_allowed_routes` and `vpn_disallowed_routes`.
    pub vpn_additional_routes: Option<Vec<String>>,
    /// Optional hostnames resolved on every connection. Resolved addresses are appended
    /// as host routes before route filters.
    pub vpn_additional_domains: Option<Vec<String>>,
    /// Optional CIDR whitelist intersected with the server and additional routes.
    /// Missing/null preserves the combined routes; an empty list allows no routes.
    pub vpn_allowed_routes: Option<Vec<String>>,
    /// Optional list of CIDR routes to exclude from AllowedIPs / system routes.
    /// Useful in full mode to punch holes for local LAN or the VPN peer IP itself,
    /// avoiding routing loops (e.g. 192.168.1.0/24, 10.0.0.5/32).
    pub vpn_disallowed_routes: Option<Vec<String>>,
    /// When set, run entirely in userspace (gVisor netstack) and expose a SOCKS5
    /// proxy at this listen address (e.g. "0.0.0.0:1080" or "127.0.0.1:1080")
    /// instead of creating a kernel TUN device. No system interface, routes, DNS
    /// changes or root privileges are required. Only TCP CONNECT is supported.
    pub socks5_listen: Option<String>,
    /// Optional SOCKS5 username/password authentication (RFC 1929). When
    /// `socks5_username` is set and non-empty, clients must authenticate with
    /// these credentials; otherwise the proxy accepts connections without auth.
    pub socks5_username: Option<String>,
    pub socks5_password: Option<String>,
    /// Force the WireGuard transport protocol instead of using the server-advertised
    /// `protocol_mode`. Accepts "udp" or "tcp" (case-insensitive). Some `protocol_mode: 1`
    /// (TCP) gateways also accept WireGuard over UDP -- for those the server even ships a
    /// `protocol_detect_config` (udp<->tcp switch thresholds) in the `/api/vpn/list` entry.
    /// Since WireGuard-over-TCP can collapse to a few KB/s on a lossy uplink (TCP-over-TCP
    /// head-of-line blocking), forcing "udp" can be far faster there. Leave unset to keep the
    /// default (follow server `protocol_mode`: 1 => tcp, otherwise udp).
    pub force_protocol: Option<String>,
    /// Optional in-process health checking and bounded recovery. Missing or
    /// disabled preserves the legacy connection lifecycle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check: Option<HealthCheckConfig>,
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match serde_json::to_string_pretty(self) {
            Ok(s) => write!(f, "{}", s),
            Err(e) => write!(f, "<invalid config: {e}>"),
        }
    }
}

impl Config {
    pub async fn from_file(file: &str) -> Result<Config> {
        let conf_str = fs::read_to_string(file)
            .await
            .with_context(|| format!("failed to read config file {file}"))?;

        let mut conf: Config = serde_json::from_str(&conf_str[..])
            .with_context(|| format!("failed to parse config file {file}"))?;

        if let Some(health_check) = conf.health_check.as_ref() {
            health_check
                .validate()
                .with_context(|| format!("invalid health_check configuration in {file}"))?;
        }

        conf.conf_file = Some(file.to_string());
        let mut update_conf = false;
        if conf.interface_name.is_none() {
            conf.interface_name = Some(DEFAULT_INTERFACE_NAME.to_string());
            update_conf = true;
        }
        if conf.device_name.is_none() {
            conf.device_name = Some(official_device_name());
            conf.state = Some(State::Init);
            update_conf = true;
        }
        if conf.device_id.is_none() {
            conf.device_id = Some(generate_device_id());
            conf.state = Some(State::Init);
            update_conf = true;
        }
        match &conf.private_key {
            Some(private_key) => match conf.public_key {
                Some(_) => {
                    // both keys exist, do nothing
                }
                None => {
                    // only private key exists, generate public from private
                    let public_key = utils::gen_public_key_from_private(private_key)?;
                    conf.public_key = Some(public_key);
                    update_conf = true;
                }
            },
            None => {
                // no key exists, generate new
                let (public_key, private_key) = utils::gen_wg_keypair();
                (conf.public_key, conf.private_key) = (Some(public_key), Some(private_key));
                update_conf = true;
            }
        }
        if update_conf {
            conf.save().await?;
        }
        Ok(conf)
    }

    pub async fn save(&self) -> Result<()> {
        let file = self
            .conf_file
            .as_ref()
            .context("config file path missing")?;
        let data = format!("{}", &self);
        fs::write(file, data)
            .await
            .with_context(|| format!("failed to write config file {file}"))?;
        Ok(())
    }
}

pub fn default_config_path() -> Result<PathBuf> {
    #[cfg(windows)]
    let home = env::var_os("USERPROFILE").or_else(|| env::var_os("HOME"));
    #[cfg(not(windows))]
    let home = env::var_os("HOME").or_else(|| env::var_os("USERPROFILE"));
    let home = home.context("failed to locate the user home directory")?;
    Ok(PathBuf::from(home).join(DEFAULT_CONFIG_FILE_NAME))
}

/// Creates a user configuration without overwriting an existing file.
/// Returns true only when a new file was created.
pub fn create_config_if_missing(
    path: &Path,
    company_name: &str,
    username: &str,
    platform: &str,
) -> Result<bool> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    match options.open(path) {
        Ok(mut file) => {
            let data = serde_json::to_string_pretty(&serde_json::json!({
                "company_name": company_name,
                "username": username,
                "password": null,
                "platform": platform,
                "vpn_mfa_type": "push",
                "auto_setup_routes": true,
                "route_mode": "split",
                "use_vpn_dns": false
            }))?;
            file.write_all(format!("{data}\n").as_bytes())
                .with_context(|| format!("failed to write config file {}", path.display()))?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("failed to create config file {}", path.display()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn generated_device_ids_match_official_shape_and_are_unique() {
        let first = generate_device_id();
        let second = generate_device_id();

        assert_eq!(first.len(), 32);
        assert!(first.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert_ne!(first, second);
    }

    #[test]
    fn default_config_template_is_valid() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!("feilian-cli-template-{unique}.json"));

        assert!(create_config_if_missing(
            &path,
            "example-company",
            "user@example.com",
            PLATFORM_CORPLINK_QR,
        )
        .unwrap());
        let config: Config =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(config.company_name, "example-company");
        assert_eq!(config.username, "user@example.com");
        assert_eq!(config.platform.as_deref(), Some(PLATFORM_CORPLINK_QR));
        assert_eq!(config.vpn_mfa_type.as_deref(), Some("push"));
        assert_eq!(config.route_mode, Some(RouteMode::Split));

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn default_config_creation_never_overwrites() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = env::temp_dir().join(format!("feilian-cli-{unique}.json"));

        assert!(create_config_if_missing(
            &path,
            "first-company",
            "first@example.com",
            PLATFORM_CORPLINK_QR,
        )
        .unwrap());
        let original = std::fs::read_to_string(&path).unwrap();
        assert!(!create_config_if_missing(
            &path,
            "second-company",
            "second@example.com",
            PLATFORM_CORPLINK_EMAIL,
        )
        .unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn legacy_config_without_health_check_still_deserializes() {
        let config: Config = serde_json::from_str(
            r#"{
                "company_name": "example-company",
                "username": "user@example.com"
            }"#,
        )
        .unwrap();

        assert!(config.health_check.is_none());
    }

    #[test]
    fn health_check_defaults_and_fields_deserialize() {
        let config: Config = serde_json::from_str(
            r#"{
                "company_name": "example-company",
                "username": "user@example.com",
                "health_check": {
                    "enabled": true,
                    "targets": [{"url": "https://internal.example.com/"}],
                    "interval_seconds": 30,
                    "failure_threshold": 2
                }
            }"#,
        )
        .unwrap();
        let health = config.health_check.unwrap();

        assert!(health.enabled);
        assert_eq!(health.targets[0].url, "https://internal.example.com/");
        assert_eq!(health.interval_seconds, 30);
        assert_eq!(health.failure_threshold, 2);
        assert_eq!(
            health.initial_delay_seconds,
            DEFAULT_HEALTH_INITIAL_DELAY_SECONDS
        );
        assert_eq!(
            health.dns_timeout_seconds,
            DEFAULT_HEALTH_DNS_TIMEOUT_SECONDS
        );
        assert_eq!(
            health.request_timeout_seconds,
            DEFAULT_HEALTH_REQUEST_TIMEOUT_SECONDS
        );
        assert_eq!(
            health.recovery_cooldown_seconds,
            DEFAULT_HEALTH_RECOVERY_COOLDOWN_SECONDS
        );
        assert_eq!(
            health.max_recovery_attempts,
            DEFAULT_HEALTH_MAX_RECOVERY_ATTEMPTS
        );
    }

    #[test]
    fn invalid_enabled_health_check_is_rejected() {
        let health = HealthCheckConfig {
            enabled: true,
            targets: vec![HealthCheckTarget {
                url: "file:///tmp/private".to_string(),
            }],
            ..HealthCheckConfig::default()
        };

        assert!(health.validate().is_err());
    }

    #[test]
    fn enabled_health_check_can_use_server_targets() {
        let health = HealthCheckConfig {
            enabled: true,
            ..HealthCheckConfig::default()
        };

        assert!(health.validate().is_ok());
    }
}

#[derive(Serialize, Clone)]
pub struct WgConf {
    // standard wg conf
    pub address: String,
    pub address6: String,
    pub peer_address: String,
    pub mtu: u32,
    pub public_key: String,
    pub private_key: String,
    pub peer_key: String,
    pub allowed_ips: Vec<String>,
    pub routes: Vec<String>,

    // extra confs
    pub dns: String,
    pub dns_domains: Vec<String>,

    // corplink confs
    pub protocol: i32,
}
