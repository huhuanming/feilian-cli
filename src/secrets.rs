use std::sync::{Arc, Mutex};

#[cfg(any(target_os = "macos", test))]
use anyhow::anyhow;
use anyhow::Result;
use serde::{Deserialize, Serialize};
#[cfg(target_os = "macos")]
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

const SECRET_BUNDLE_VERSION: u32 = 1;
#[cfg(target_os = "macos")]
const KEYCHAIN_SERVICE: &str = "org.feilian-cli.credentials.v1";

#[derive(Default, Deserialize, Serialize)]
struct SecretBundle {
    version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    socks5_password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cookies_json: Option<String>,
}

impl SecretBundle {
    fn empty() -> Self {
        Self {
            version: SECRET_BUNDLE_VERSION,
            password: None,
            code: None,
            private_key: None,
            socks5_password: None,
            cookies_json: None,
        }
    }

    fn zeroize_secrets(&mut self) {
        zeroize_secret(&mut self.password);
        zeroize_secret(&mut self.code);
        zeroize_secret(&mut self.private_key);
        zeroize_secret(&mut self.socks5_password);
        zeroize_secret(&mut self.cookies_json);
    }
}

impl Drop for SecretBundle {
    fn drop(&mut self) {
        self.zeroize_secrets();
    }
}

fn zeroize_secret(secret: &mut Option<String>) {
    if let Some(value) = secret.as_mut() {
        value.zeroize();
    }
}

fn replace_secret(secret: &mut Option<String>, replacement: Option<String>) {
    zeroize_secret(secret);
    *secret = replacement;
}

trait SecretPersistence: Send + Sync {
    fn load(&self) -> Result<Option<Vec<u8>>>;
    fn save(&self, data: &[u8]) -> Result<()>;
}

#[cfg(test)]
struct TestPersistence;

#[cfg(test)]
impl SecretPersistence for TestPersistence {
    fn load(&self) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    fn save(&self, _data: &[u8]) -> Result<()> {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
struct KeychainPersistence {
    account: String,
}

#[cfg(target_os = "macos")]
impl KeychainPersistence {
    fn new(device_id: &str) -> Self {
        // device_id is already opaque, but hashing it keeps the Keychain item
        // identity from exposing any profile metadata if that format changes.
        let account = hex::encode(Sha256::digest(device_id.as_bytes()));
        Self { account }
    }
}

#[cfg(target_os = "macos")]
impl SecretPersistence for KeychainPersistence {
    fn load(&self) -> Result<Option<Vec<u8>>> {
        use security_framework::passwords::get_generic_password;
        use security_framework_sys::base::errSecItemNotFound;

        match get_generic_password(KEYCHAIN_SERVICE, &self.account) {
            Ok(data) => Ok(Some(data)),
            Err(error) if error.code() == errSecItemNotFound => Ok(None),
            Err(_) => Err(anyhow!("macOS Keychain read failed")),
        }
    }

    fn save(&self, data: &[u8]) -> Result<()> {
        security_framework::passwords::set_generic_password(KEYCHAIN_SERVICE, &self.account, data)
            .map_err(|_| anyhow!("macOS Keychain write failed"))
    }
}

struct SecretStoreInner {
    bundle: SecretBundle,
    persistence: Option<Arc<dyn SecretPersistence>>,
    persisted: bool,
}

/// Process-local secret state with optional macOS Keychain persistence.
///
/// This type intentionally has no `Debug` implementation. Persistence errors
/// switch the instance to memory-only mode and never fall back to a file.
#[derive(Clone)]
pub struct SecretStore {
    inner: Arc<Mutex<SecretStoreInner>>,
}

impl Default for SecretStore {
    fn default() -> Self {
        Self::memory()
    }
}

impl SecretStore {
    pub fn for_profile(device_id: &str) -> Self {
        #[cfg(target_os = "macos")]
        {
            Self::from_persistence(Arc::new(KeychainPersistence::new(device_id)))
        }

        #[cfg(not(target_os = "macos"))]
        {
            let _ = device_id;
            Self::memory()
        }
    }

    pub fn memory() -> Self {
        Self {
            inner: Arc::new(Mutex::new(SecretStoreInner {
                bundle: SecretBundle::empty(),
                persistence: None,
                persisted: false,
            })),
        }
    }

    #[cfg(test)]
    pub(crate) fn persistent_for_test(cookies_json: &str) -> Self {
        Self {
            inner: Arc::new(Mutex::new(SecretStoreInner {
                bundle: SecretBundle {
                    version: SECRET_BUNDLE_VERSION,
                    password: None,
                    code: None,
                    private_key: None,
                    socks5_password: None,
                    cookies_json: Some(cookies_json.to_string()),
                },
                persistence: Some(Arc::new(TestPersistence)),
                persisted: true,
            })),
        }
    }

    fn from_persistence(persistence: Arc<dyn SecretPersistence>) -> Self {
        match persistence.load() {
            Ok(Some(mut data)) => {
                let bundle = serde_json::from_slice::<SecretBundle>(&data);
                data.zeroize();
                match bundle {
                    Ok(bundle) if bundle.version == SECRET_BUNDLE_VERSION => Self {
                        inner: Arc::new(Mutex::new(SecretStoreInner {
                            bundle,
                            persistence: Some(persistence),
                            persisted: true,
                        })),
                    },
                    _ => {
                        log::warn!(
                            "secure credential store contains unsupported data; using memory-only authentication"
                        );
                        Self::memory()
                    }
                }
            }
            Ok(None) => Self {
                inner: Arc::new(Mutex::new(SecretStoreInner {
                    bundle: SecretBundle::empty(),
                    persistence: Some(persistence),
                    persisted: false,
                })),
            },
            Err(_) => {
                log::warn!(
                    "secure credential store is unavailable; using memory-only authentication"
                );
                Self::memory()
            }
        }
    }

    fn with_inner<T>(&self, f: impl FnOnce(&mut SecretStoreInner) -> T) -> T {
        let mut inner = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        f(&mut inner)
    }

    fn persist(inner: &mut SecretStoreInner) -> bool {
        let Some(persistence) = inner.persistence.clone() else {
            inner.persisted = false;
            return false;
        };
        let mut data = match serde_json::to_vec(&inner.bundle) {
            Ok(data) => data,
            Err(_) => {
                log::warn!(
                    "secure credential serialization failed; using memory-only authentication"
                );
                inner.persistence = None;
                inner.persisted = false;
                return false;
            }
        };
        let result = persistence.save(&data);
        data.zeroize();
        match result {
            Ok(()) => {
                inner.persisted = true;
                true
            }
            Err(_) => {
                log::warn!(
                    "secure credential store update failed; using memory-only authentication"
                );
                inner.persistence = None;
                inner.persisted = false;
                false
            }
        }
    }

    pub fn config_secrets(
        &self,
    ) -> (
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
    ) {
        self.with_inner(|inner| {
            (
                inner.bundle.password.clone(),
                inner.bundle.code.clone(),
                inner.bundle.private_key.clone(),
                inner.bundle.socks5_password.clone(),
            )
        })
    }

    pub fn update_config_secrets(
        &self,
        password: Option<&str>,
        code: Option<&str>,
        private_key: Option<&str>,
        socks5_password: Option<&str>,
    ) -> bool {
        self.with_inner(|inner| {
            replace_secret(&mut inner.bundle.password, password.map(str::to_owned));
            replace_secret(&mut inner.bundle.code, code.map(str::to_owned));
            replace_secret(
                &mut inner.bundle.private_key,
                private_key.map(str::to_owned),
            );
            replace_secret(
                &mut inner.bundle.socks5_password,
                socks5_password.map(str::to_owned),
            );
            Self::persist(inner)
        })
    }

    pub fn cookies_json(&self) -> Option<String> {
        self.with_inner(|inner| inner.bundle.cookies_json.clone())
    }

    pub fn update_cookies(&self, mut cookies_json: String) -> bool {
        let replacement = if cookies_json.trim().is_empty() {
            cookies_json.zeroize();
            None
        } else {
            Some(cookies_json)
        };
        self.with_inner(|inner| {
            replace_secret(&mut inner.bundle.cookies_json, replacement);
            Self::persist(inner)
        })
    }

    pub fn clear_session(&self) -> bool {
        self.with_inner(|inner| {
            replace_secret(&mut inner.bundle.cookies_json, None);
            Self::persist(inner)
        })
    }

    pub fn can_resume_session(&self) -> bool {
        self.with_inner(|inner| {
            inner.persistence.is_some() && inner.persisted && inner.bundle.cookies_json.is_some()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakePersistence {
        data: Mutex<Option<Vec<u8>>>,
        fail_load: bool,
        fail_save: bool,
    }

    impl SecretPersistence for FakePersistence {
        fn load(&self) -> Result<Option<Vec<u8>>> {
            if self.fail_load {
                return Err(anyhow!("synthetic read failure"));
            }
            Ok(self.data.lock().unwrap().clone())
        }

        fn save(&self, data: &[u8]) -> Result<()> {
            if self.fail_save {
                return Err(anyhow!("synthetic write failure"));
            }
            *self.data.lock().unwrap() = Some(data.to_vec());
            Ok(())
        }
    }

    fn fake(initial: Option<Vec<u8>>, fail_load: bool, fail_save: bool) -> SecretStore {
        SecretStore::from_persistence(Arc::new(FakePersistence {
            data: Mutex::new(initial),
            fail_load,
            fail_save,
        }))
    }

    #[test]
    fn memory_store_never_claims_persistence() {
        let store = SecretStore::memory();
        assert!(!store.update_cookies("[]".to_string()));
        assert_eq!(store.cookies_json().as_deref(), Some("[]"));
        assert!(!store.can_resume_session());
        assert!(SecretStore::memory().cookies_json().is_none());
    }

    #[test]
    fn secret_zeroize_helper_clears_string_contents() {
        let mut secret = Some("synthetic-secret".to_string());
        zeroize_secret(&mut secret);
        assert!(secret.as_ref().is_some_and(String::is_empty));

        replace_secret(&mut secret, Some("replacement".to_string()));
        assert_eq!(secret.as_deref(), Some("replacement"));
        replace_secret(&mut secret, None);
        assert!(secret.is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn keychain_identity_does_not_expose_profile_metadata() {
        let persistence = KeychainPersistence::new("synthetic-user@example.com");
        assert_eq!(persistence.account.len(), 64);
        assert!(!persistence.account.contains("synthetic-user"));
        assert!(!persistence.account.contains('@'));
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "accesses one uniquely named synthetic macOS Keychain item"]
    fn synthetic_keychain_roundtrip() {
        use std::time::{SystemTime, UNIX_EPOCH};

        use security_framework::passwords::delete_generic_password;
        use zeroize::Zeroizing;

        struct Cleanup {
            account: String,
        }

        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = delete_generic_password(KEYCHAIN_SERVICE, &self.account);
            }
        }

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time before unix epoch")
            .as_nanos();
        let profile = format!("synthetic-keychain-test-{}-{unique}", std::process::id());
        let persistence = KeychainPersistence::new(&profile);
        let _cleanup = Cleanup {
            account: persistence.account.clone(),
        };
        let data = Zeroizing::new(format!("synthetic-secret-{unique}").into_bytes());

        persistence
            .save(&data)
            .expect("write synthetic Keychain item");
        let loaded = Zeroizing::new(
            persistence
                .load()
                .expect("read synthetic Keychain item")
                .expect("synthetic Keychain item missing"),
        );
        assert_eq!(&*loaded, &*data);

        delete_generic_password(KEYCHAIN_SERVICE, &persistence.account)
            .expect("delete synthetic Keychain item");
        assert!(persistence
            .load()
            .expect("confirm synthetic Keychain deletion")
            .is_none());
    }

    #[test]
    fn failed_read_starts_empty_in_memory() {
        let store = fake(None, true, false);
        assert!(store.cookies_json().is_none());
        assert!(!store.can_resume_session());
    }

    #[test]
    fn failed_write_keeps_current_process_data_only() {
        let store = fake(None, false, true);
        assert!(!store.update_cookies("synthetic-cookie-json".to_string()));
        assert_eq!(
            store.cookies_json().as_deref(),
            Some("synthetic-cookie-json")
        );
        assert!(!store.can_resume_session());
    }

    #[test]
    fn session_clear_preserves_long_lived_secrets() {
        let store = fake(None, false, false);
        assert!(store.update_config_secrets(None, Some("totp"), Some("private"), None));
        assert!(store.update_cookies("synthetic-cookie-json".to_string()));
        assert!(store.clear_session());
        assert!(store.cookies_json().is_none());
        let (_, code, private_key, _) = store.config_secrets();
        assert_eq!(code.as_deref(), Some("totp"));
        assert_eq!(private_key.as_deref(), Some("private"));
    }

    #[test]
    fn persistent_backend_receives_one_versioned_bundle() {
        let persistence = Arc::new(FakePersistence {
            data: Mutex::new(None),
            fail_load: false,
            fail_save: false,
        });
        let store = SecretStore::from_persistence(persistence.clone());

        assert!(store.update_config_secrets(None, Some("totp"), Some("private"), None));
        assert!(store.update_cookies("synthetic-cookie-json".to_string()));
        assert!(store.can_resume_session());

        let data = persistence.data.lock().unwrap().clone().unwrap();
        let bundle: SecretBundle = serde_json::from_slice(&data).unwrap();
        assert_eq!(bundle.version, SECRET_BUNDLE_VERSION);
        assert_eq!(bundle.code.as_deref(), Some("totp"));
        assert_eq!(bundle.private_key.as_deref(), Some("private"));
        assert_eq!(
            bundle.cookies_json.as_deref(),
            Some("synthetic-cookie-json")
        );
    }

    #[test]
    fn session_clear_failure_never_restores_memory_session() {
        let bundle = SecretBundle {
            version: SECRET_BUNDLE_VERSION,
            password: None,
            code: None,
            private_key: None,
            socks5_password: None,
            cookies_json: Some("synthetic-cookie-json".to_string()),
        };
        let store = fake(Some(serde_json::to_vec(&bundle).unwrap()), false, true);
        assert!(store.can_resume_session());
        assert!(!store.clear_session());
        assert!(store.cookies_json().is_none());
        assert!(!store.can_resume_session());
    }
}
