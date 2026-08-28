use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Component;
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;
use tokio::fs;

use anyhow::{bail, Context, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::secrets::SecretStore;
use crate::state::State;
use crate::utils;

#[cfg(target_os = "macos")]
const DEFAULT_INTERFACE_NAME: &str = "utun12345";
#[cfg(not(target_os = "macos"))]
const DEFAULT_INTERFACE_NAME: &str = "corplink";
pub const DEFAULT_CONFIG_FILE_NAME: &str = "feilian-cli.config.json";
const LEGACY_COOKIE_FILE_SUFFIX: &str = "cookies.json";

pub const DEFAULT_HEALTH_INTERVAL_SECONDS: u64 = 5 * 60;
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

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub company_name: String,
    pub username: String,
    #[serde(default, skip_serializing)]
    pub password: Option<String>,
    pub platform: Option<String>,
    #[serde(default, skip_serializing)]
    pub code: Option<String>,
    pub device_name: Option<String>,
    pub device_id: Option<String>,
    pub public_key: Option<String>,
    #[serde(default, skip_serializing)]
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
    #[serde(default, skip_serializing)]
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
    #[serde(skip, default)]
    pub(crate) secret_store: SecretStore,
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
        Self::from_file_with_store(file, None).await
    }

    async fn from_file_with_store(file: &str, store: Option<SecretStore>) -> Result<Config> {
        let mut conf_str = fs::read_to_string(file)
            .await
            .with_context(|| format!("failed to read config file {file}"))?;

        let parsed = serde_json::from_str(&conf_str[..])
            .with_context(|| format!("failed to parse config file {file}"));
        conf_str.zeroize();
        let mut conf: Config = parsed?;

        let legacy_password = discard_plaintext_secret(&mut conf.password);
        let legacy_code = discard_plaintext_secret(&mut conf.code);
        let legacy_private_key = discard_plaintext_secret(&mut conf.private_key);
        let legacy_socks5_password = discard_plaintext_secret(&mut conf.socks5_password);
        let legacy_plaintext =
            legacy_password || legacy_code || legacy_private_key || legacy_socks5_password;

        if let Some(health_check) = conf.health_check.as_ref() {
            health_check
                .validate()
                .with_context(|| format!("invalid health_check configuration in {file}"))?;
        }

        conf.conf_file = Some(file.to_string());
        let mut update_conf = legacy_plaintext;
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

        let interface_name = conf
            .interface_name
            .as_deref()
            .context("interface name missing")?;
        let legacy_cookie_found = remove_legacy_cookie(file, interface_name).await;
        let force_fresh_login = legacy_plaintext || legacy_cookie_found;

        let device_id = conf.device_id.as_deref().context("device_id missing")?;
        conf.secret_store = store.unwrap_or_else(|| SecretStore::for_profile(device_id));
        if force_fresh_login {
            conf.secret_store.clear_session();
            conf.state = Some(State::Init);
            update_conf = true;
            log::debug!("legacy plaintext credentials disabled");
        }

        let (mut password, mut code, mut stored_private_key, mut socks5_password) =
            conf.secret_store.config_secrets();
        if stored_private_key
            .as_ref()
            .is_some_and(|private_key| utils::gen_public_key_from_private(private_key).is_err())
        {
            log::warn!(
                "secure credential store contains an invalid key; using memory-only authentication"
            );
            conf.secret_store = SecretStore::memory();
            password = None;
            code = None;
            stored_private_key = None;
            socks5_password = None;
            conf.state = Some(State::Init);
            update_conf = true;
        }
        conf.password = password;
        conf.code = code;
        conf.socks5_password = socks5_password;

        if legacy_private_key {
            conf.public_key = None;
        }
        match stored_private_key {
            Some(private_key) if !legacy_private_key => {
                let public_key = utils::gen_public_key_from_private(&private_key)?;
                if conf.public_key.as_deref() != Some(public_key.as_str()) {
                    conf.public_key = Some(public_key);
                    update_conf = true;
                }
                conf.private_key = Some(private_key);
            }
            _ => {
                let (public_key, private_key) = utils::gen_wg_keypair();
                conf.public_key = Some(public_key);
                conf.private_key = Some(private_key);
                update_conf = true;
            }
        }

        if !conf.secret_store.can_resume_session() {
            if conf.state != Some(State::Init) {
                update_conf = true;
            }
            conf.state = Some(State::Init);
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
        self.secret_store.update_config_secrets(
            self.password.as_deref(),
            self.code.as_deref(),
            self.private_key.as_deref(),
            self.socks5_password.as_deref(),
        );
        let mut value = serde_json::to_value(self).context("failed to serialize config")?;
        if self.state == Some(State::Login) && !self.secret_store.can_resume_session() {
            value["state"] = serde_json::to_value(State::Init)?;
        }
        let data = serde_json::to_string_pretty(&value).context("failed to serialize config")?;
        fs::write(file, data)
            .await
            .with_context(|| format!("failed to write config file {file}"))?;
        Ok(())
    }

    pub fn validate_runtime_secrets(&self) -> Result<()> {
        if matches!(
            self.platform.as_deref(),
            Some(PLATFORM_LDAP | PLATFORM_CORPLINK_V1)
        ) && self
            .password
            .as_deref()
            .filter(|value| !value.is_empty())
            .is_none()
        {
            bail!(
                "password-based login requires a credential from secure storage; plaintext config credentials are ignored"
            );
        }
        if self
            .socks5_username
            .as_deref()
            .is_some_and(|value| !value.is_empty())
            && self
                .socks5_password
                .as_deref()
                .filter(|value| !value.is_empty())
                .is_none()
        {
            bail!(
                "SOCKS5 username/password authentication requires a password from secure storage; plaintext config credentials are ignored"
            );
        }
        Ok(())
    }
}

fn discard_plaintext_secret(secret: &mut Option<String>) -> bool {
    let Some(mut value) = secret.take() else {
        return false;
    };
    value.zeroize();
    true
}

async fn remove_legacy_cookie(config_file: &str, interface_name: &str) -> bool {
    let interface_path = Path::new(interface_name);
    let mut components = interface_path.components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        log::warn!("legacy plaintext cookie cleanup skipped because its identity is unsafe");
        return true;
    }

    let config_path = Path::new(config_file);
    let dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let cookie_file = dir.join(format!("{interface_name}_{LEGACY_COOKIE_FILE_SUFFIX}"));
    let metadata = match fs::symlink_metadata(&cookie_file).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
        Err(_) => {
            log::warn!("legacy plaintext cookie could not be inspected; it will not be used");
            return true;
        }
    };
    if !(metadata.file_type().is_file() || metadata.file_type().is_symlink()) {
        log::warn!("legacy plaintext cookie has an unsafe file type; it will not be used");
        return true;
    }
    if fs::remove_file(cookie_file).await.is_err() {
        log::warn!("legacy plaintext cookie could not be removed; it will not be used");
    }
    true
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
        let contents = std::fs::read_to_string(&path).unwrap();
        let config: Config = serde_json::from_str(&contents).unwrap();
        assert_eq!(config.company_name, "example-company");
        assert_eq!(config.username, "user@example.com");
        assert_eq!(config.platform.as_deref(), Some(PLATFORM_CORPLINK_QR));
        assert_eq!(config.vpn_mfa_type.as_deref(), Some("push"));
        assert_eq!(config.route_mode, Some(RouteMode::Split));
        assert!(!contents.contains("password"));

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
    fn config_serialization_omits_all_authentication_secrets() {
        let mut config: Config = serde_json::from_str(
            r#"{
                "company_name": "example-company",
                "username": "user@example.com"
            }"#,
        )
        .unwrap();
        config.password = Some("synthetic-password".to_string());
        config.code = Some("synthetic-totp-seed".to_string());
        config.private_key = Some("synthetic-private-key".to_string());
        config.socks5_password = Some("synthetic-socks-password".to_string());

        let value = serde_json::to_value(config).unwrap();
        for field in ["password", "code", "private_key", "socks5_password"] {
            assert!(
                value.get(field).is_none(),
                "serialized secret field {field}"
            );
        }
    }

    fn temp_case(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = env::temp_dir().join(format!("feilian-cli-{name}-{unique}"));
        std::fs::create_dir(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn legacy_plaintext_is_never_loaded_and_is_removed() {
        let dir = temp_case("legacy-plaintext");
        let config_path = dir.join("config.json");
        let cookie_path = dir.join("test0_cookies.json");
        std::fs::write(
            &config_path,
            r#"{
                "company_name": "example-company",
                "username": "user@example.com",
                "platform": "feilian_qr",
                "interface_name": "test0",
                "device_name": "Test Device",
                "device_id": "synthetic-device-id",
                "state": "Login",
                "public_key": "legacy-public",
                "password": "legacy-password",
                "code": "legacy-totp",
                "private_key": "legacy-private",
                "socks5_password": "legacy-socks-password"
            }"#,
        )
        .unwrap();
        std::fs::write(&cookie_path, b"synthetic legacy cookie").unwrap();

        let config = Config::from_file_with_store(
            config_path.to_str().unwrap(),
            Some(SecretStore::memory()),
        )
        .await
        .unwrap();

        assert!(matches!(config.state, Some(State::Init)));
        assert!(config.password.is_none());
        assert!(config.code.is_none());
        assert!(config.socks5_password.is_none());
        assert_ne!(config.private_key.as_deref(), Some("legacy-private"));
        assert_ne!(config.public_key.as_deref(), Some("legacy-public"));
        assert!(!cookie_path.exists());

        let sanitized: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        for field in ["password", "code", "private_key", "socks5_password"] {
            assert!(
                sanitized.get(field).is_none(),
                "legacy field {field} remains"
            );
        }

        std::fs::remove_file(config_path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[tokio::test]
    async fn legacy_cookie_removal_failure_never_enables_session() {
        let dir = temp_case("cookie-removal-failure");
        let config_path = dir.join("config.json");
        let cookie_path = dir.join("test0_cookies.json");
        std::fs::write(
            &config_path,
            r#"{
                "company_name": "example-company",
                "username": "user@example.com",
                "platform": "feilian_qr",
                "interface_name": "test0",
                "device_name": "Test Device",
                "device_id": "synthetic-device-id",
                "state": "Login"
            }"#,
        )
        .unwrap();
        std::fs::create_dir(&cookie_path).unwrap();

        let config = Config::from_file_with_store(
            config_path.to_str().unwrap(),
            Some(SecretStore::memory()),
        )
        .await
        .unwrap();

        assert!(matches!(config.state, Some(State::Init)));
        assert!(config.secret_store.cookies_json().is_none());
        assert!(cookie_path.is_dir());

        std::fs::remove_dir(cookie_path).unwrap();
        std::fs::remove_file(config_path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[tokio::test]
    async fn login_state_requires_a_persisted_secure_session() {
        let dir = temp_case("state-session");
        let config_path = dir.join("config.json");
        let config_json = r#"{
            "company_name": "example-company",
            "username": "user@example.com",
            "platform": "feilian_qr",
            "interface_name": "test0",
            "device_name": "Test Device",
            "device_id": "synthetic-device-id",
            "state": "Login"
        }"#;
        std::fs::write(&config_path, config_json).unwrap();

        let without_session = Config::from_file_with_store(
            config_path.to_str().unwrap(),
            Some(SecretStore::memory()),
        )
        .await
        .unwrap();
        assert!(matches!(without_session.state, Some(State::Init)));
        let saved: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(saved["state"], "Init");

        std::fs::write(&config_path, config_json).unwrap();
        let with_session = Config::from_file_with_store(
            config_path.to_str().unwrap(),
            Some(SecretStore::persistent_for_test("synthetic-secure-session")),
        )
        .await
        .unwrap();
        assert!(matches!(with_session.state, Some(State::Login)));
        let saved: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
        assert_eq!(saved["state"], "Login");

        std::fs::remove_file(config_path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn legacy_cookie_symlink_is_removed_without_touching_target() {
        use std::os::unix::fs::symlink;

        let dir = temp_case("cookie-symlink");
        let config_path = dir.join("config.json");
        let cookie_path = dir.join("test0_cookies.json");
        let target_path = dir.join("unrelated.txt");
        std::fs::write(
            &config_path,
            r#"{
                "company_name": "example-company",
                "username": "user@example.com",
                "platform": "feilian_qr",
                "interface_name": "test0",
                "device_name": "Test Device",
                "device_id": "synthetic-device-id",
                "state": "Login"
            }"#,
        )
        .unwrap();
        std::fs::write(&target_path, b"keep this file").unwrap();
        symlink(&target_path, &cookie_path).unwrap();

        let config = Config::from_file_with_store(
            config_path.to_str().unwrap(),
            Some(SecretStore::memory()),
        )
        .await
        .unwrap();

        assert!(matches!(config.state, Some(State::Init)));
        assert!(!cookie_path.exists());
        assert_eq!(std::fs::read(&target_path).unwrap(), b"keep this file");

        std::fs::remove_file(target_path).unwrap();
        std::fs::remove_file(config_path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn missing_secure_passwords_fail_closed_for_dependent_modes() {
        let mut config: Config = serde_json::from_str(
            r#"{
                "company_name": "example-company",
                "username": "user@example.com",
                "platform": "feilian_v1",
                "socks5_username": "local-user"
            }"#,
        )
        .unwrap();
        let error = config.validate_runtime_secrets().unwrap_err().to_string();
        assert!(error.contains("secure storage"));
        assert!(!error.contains("user@example.com"));

        config.platform = Some(PLATFORM_CORPLINK_QR.to_string());
        let error = config.validate_runtime_secrets().unwrap_err().to_string();
        assert!(error.contains("SOCKS5"));
        assert!(!error.contains("local-user"));
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
        assert_eq!(health.interval_seconds, 300);
    }

    #[test]
    fn dynamic_dns_records_are_normalized_and_prefer_exact_matches() {
        let mut policy = NetstackDnsPolicy::default();
        policy.exact_v4.insert(
            "host.internal.example.com".to_string(),
            vec!["10.0.0.10/32".to_string()],
        );
        policy.wildcard_v4.insert(
            "internal.example.com".to_string(),
            vec!["10.0.0.11".to_string()],
        );

        assert_eq!(
            policy.dynamic_addresses("HOST.INTERNAL.EXAMPLE.COM."),
            Some(vec!["10.0.0.10".parse().unwrap()])
        );
    }

    #[test]
    fn split_dns_suffixes_match_apex_and_subdomains_only() {
        let policy = NetstackDnsPolicy {
            split_domains: vec!["*.internal.example.com".to_string()],
            ..NetstackDnsPolicy::default()
        };

        assert!(policy.matches_split_domain("internal.example.com"));
        assert!(policy.matches_split_domain("host.internal.example.com"));
        assert!(!policy.matches_split_domain("notinternal.example.com"));
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
    pub dns_policy: NetstackDnsPolicy,

    // corplink confs
    pub protocol: i32,
}

#[derive(Serialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct NetstackDnsPolicy {
    pub split_domains: Vec<String>,
    pub split_dns_servers: Vec<String>,
    pub exact_v4: BTreeMap<String, Vec<String>>,
    pub exact_v6: BTreeMap<String, Vec<String>>,
    pub wildcard_v4: BTreeMap<String, Vec<String>>,
    pub suffix_v4: BTreeMap<String, Vec<String>>,
}

impl NetstackDnsPolicy {
    pub fn matches_split_domain(&self, host: &str) -> bool {
        let host = normalize_dns_name(host);
        self.split_domains.iter().any(|suffix| {
            let suffix = normalize_dns_name(suffix);
            !suffix.is_empty() && (host == suffix || host.ends_with(&format!(".{suffix}")))
        })
    }

    pub fn dynamic_addresses(&self, host: &str) -> Option<Vec<std::net::IpAddr>> {
        let host = normalize_dns_name(host);
        if self.exact_v4.contains_key(&host) || self.exact_v6.contains_key(&host) {
            let values = self
                .exact_v4
                .get(&host)
                .into_iter()
                .chain(self.exact_v6.get(&host))
                .flatten();
            return Some(dynamic_values_to_addresses(values));
        }
        for records in [&self.wildcard_v4, &self.suffix_v4] {
            if let Some((_, values)) = records
                .iter()
                .filter(|(suffix, _)| dns_suffix_matches(&host, suffix))
                .max_by_key(|(suffix, _)| normalize_dns_name(suffix).len())
            {
                return Some(dynamic_values_to_addresses(values));
            }
        }
        None
    }
}

fn dynamic_values_to_addresses<'a>(
    values: impl IntoIterator<Item = &'a String>,
) -> Vec<std::net::IpAddr> {
    let mut addresses = Vec::new();
    for value in values {
        let value = value.split('/').next().unwrap_or(value).trim();
        if let Ok(address) = value.parse() {
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
    }
    addresses
}

pub(crate) fn normalize_dns_name(value: &str) -> String {
    value
        .trim()
        .trim_matches(['\"', '\''])
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

fn dns_suffix_matches(host: &str, suffix: &str) -> bool {
    let suffix = normalize_dns_name(suffix);
    !suffix.is_empty() && (host == suffix || host.ends_with(&format!(".{suffix}")))
}
