use std::collections::BTreeMap;

#[derive(serde::Deserialize, Debug)]
pub struct Resp<T> {
    pub code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
pub struct RespCompany {
    pub name: String,
    pub zh_name: String,
    pub en_name: String,
    pub domain: String,
    pub enable_self_signed: bool,
    pub self_signed_cert: String,
    pub enable_public_key: bool,
    pub public_key: String,
}

#[derive(serde::Deserialize, Debug)]
pub struct RespLoginMethod {
    pub login_enable_ldap: bool,
    pub login_enable: bool,
    pub login_orders: Vec<String>,
    #[serde(default)]
    pub scan_code_login_url: Option<String>,
}

#[derive(serde::Deserialize, Debug)]
pub struct RespTpsLoginMethod {
    pub alias: String,
    pub login_url: String,
    pub token: String,
}

#[derive(serde::Deserialize, Debug)]
pub struct RespCorplinkLoginMethod {
    pub mfa: bool,
    pub auth: Vec<String>,
}

#[derive(serde::Deserialize, Debug)]
pub struct RespLogin {
    #[serde(default)]
    pub url: String,
}

// response of the v1 login endpoint (/api/v1/login), e.g.
// {"result":"success","next":{"action":"GoToLink","can_skip":false}}
#[derive(serde::Deserialize, Debug)]
pub struct RespLoginV1 {
    #[serde(default)]
    pub result: String,
}

#[derive(serde::Deserialize, Debug)]
pub struct RespQrToken {
    pub token: String,
}

#[derive(serde::Deserialize, Debug)]
pub struct RespQrCheck {
    #[serde(default)]
    pub result: String,
}

#[derive(serde::Deserialize, Debug, Default)]
pub struct RespVpnMfaType {
    #[serde(default)]
    pub vpn_types: Vec<String>,
    #[serde(default)]
    pub types: Vec<String>,
}

#[derive(serde::Deserialize, Debug)]
pub struct RespOtp {
    pub url: String,
    pub code: String,
}

#[derive(serde::Deserialize, Debug)]
pub struct RespVpnInfo {
    pub api_port: u16,
    pub vpn_port: u16,
    pub ip: String,
    // 1 for tcp, 2 for udp, we only support udp for now
    pub protocol_mode: i32,
    // useless
    pub name: String,
    pub en_name: String,
    pub icon: String,
    pub id: i32,
    pub timeout: i32,
}

#[derive(serde::Deserialize, Debug)]
pub struct RespWgExtraInfo {
    pub vpn_mtu: u32,
    pub vpn_dns: String,
    pub vpn_dns_backup: String,
    pub vpn_dns_domain_split: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_optional_stringified_map")]
    pub vpn_dynamic_domain_route_split: Option<BTreeMap<String, Vec<String>>>,
    #[serde(default, deserialize_with = "deserialize_optional_stringified_map")]
    pub v6_vpn_dynamic_domain_route_split: Option<BTreeMap<String, Vec<String>>>,
    #[serde(default, deserialize_with = "deserialize_optional_stringified_map")]
    pub vpn_wildcard_dynamic_domain_route_split: Option<BTreeMap<String, Vec<String>>>,
    #[serde(default, deserialize_with = "deserialize_optional_stringified_map")]
    pub suffix_wildcard_dynamic_domain_route_split: Option<BTreeMap<String, Vec<String>>>,
    #[serde(default, deserialize_with = "deserialize_optional_stringified_map")]
    pub dynamic_domain: Option<BTreeMap<String, Vec<String>>>,
    #[serde(
        default,
        deserialize_with = "deserialize_optional_stringified_central_dns"
    )]
    pub central_dns: Option<RespCentralDns>,
    pub vpn_route_full: Vec<String>,
    pub vpn_route_split: Vec<String>,
    pub v6_route_full: Option<Vec<String>>,
    pub v6_route_split: Option<Vec<String>>,
}

#[derive(serde::Deserialize, Debug, Default)]
pub struct RespCentralDns {
    #[serde(default, rename = "DNATIp")]
    pub dnat_ip: String,
}

fn deserialize_optional_stringified_map<'de, D>(
    deserializer: D,
) -> Result<Option<BTreeMap<String, Vec<String>>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_stringified(deserializer)
}

fn deserialize_optional_stringified_central_dns<'de, D>(
    deserializer: D,
) -> Result<Option<RespCentralDns>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    deserialize_optional_stringified(deserializer)
}

fn deserialize_optional_stringified<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    use serde::Deserialize as _;

    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    Ok(match value {
        Some(serde_json::Value::String(encoded)) => {
            let encoded = encoded.trim();
            (!encoded.is_empty())
                .then(|| serde_json::from_str(encoded).ok())
                .flatten()
        }
        Some(serde_json::Value::Null) | None => None,
        Some(value) => serde_json::from_value(value).ok(),
    })
}

#[derive(serde::Deserialize, Debug)]
pub struct RespWgInfo {
    pub ip: String,
    pub ipv6: String,
    pub ip_mask: String,
    pub public_key: String,
    pub setting: RespWgExtraInfo,
    pub mode: u32,
}

#[cfg(test)]
mod tests {
    use super::RespWgExtraInfo;

    fn base_setting() -> serde_json::Value {
        serde_json::json!({
            "vpn_mtu": 1400,
            "vpn_dns": "10.0.0.53",
            "vpn_dns_backup": "",
            "vpn_dns_domain_split": ["internal.example.com"],
            "vpn_route_full": [],
            "vpn_route_split": [],
            "v6_route_full": [],
            "v6_route_split": []
        })
    }

    #[test]
    fn parses_stringified_dynamic_dns_records() {
        let mut setting = base_setting();
        setting["vpn_dynamic_domain_route_split"] =
            serde_json::Value::String(r#"{"internal.example.com":["10.0.0.10/32"]}"#.to_string());
        setting["central_dns"] = serde_json::Value::String(r#"{"DNATIp":"10.0.0.53"}"#.to_string());

        let parsed: RespWgExtraInfo = serde_json::from_value(setting).unwrap();
        assert_eq!(
            parsed.vpn_dynamic_domain_route_split.unwrap()["internal.example.com"],
            ["10.0.0.10/32"]
        );
        assert_eq!(parsed.central_dns.unwrap().dnat_ip, "10.0.0.53");
    }

    #[test]
    fn parses_native_dynamic_dns_records() {
        let mut setting = base_setting();
        setting["dynamic_domain"] = serde_json::json!({
            "internal.example.com": ["10.0.0.11"]
        });

        let parsed: RespWgExtraInfo = serde_json::from_value(setting).unwrap();
        assert_eq!(
            parsed.dynamic_domain.unwrap()["internal.example.com"],
            ["10.0.0.11"]
        );
    }
}
