//! The optional config file.
//!
//! Looked up in this order: `--config <path>`, `$MDMSIGN_CONFIG`,
//! `$XDG_CONFIG_HOME/mdmsign/config.toml`, `~/.config/mdmsign/config.toml`.
//! Secrets are never stored in it; it can only name the environment variable
//! that holds a secret.
//!
//! ```toml
//! [signing]
//! identity = "Developer ID Installer: Example Corp (ABCDE12345)"  # macOS Keychain
//! # p12_path = "~/certs/installer.p12"
//! # p12_password_env = "INSTALLER_P12_PASSWORD"
//! # timestamp = true
//! # backend = "auto"   # auto | native | apple
//!
//! [notarize]
//! key_path = "~/.appstoreconnect/AuthKey_ABC123DEFG.p8"
//! key_id = "ABC123DEFG"
//! issuer_id = "00000000-0000-0000-0000-000000000000"
//! # timeout_minutes = 30
//!
//! [package]   # mdmsign pkg
//! # identifier_prefix = "com.example.pkg"   # package ID = prefix + app bundle ID
//! # install_location = "/Applications"
//! ```

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::{credentials::Env, sign::Backend};

/// Errors loading the config file.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConfigError {
    #[error("config file not found: {}", .0.display())]
    NotFound(PathBuf),

    #[error("couldn't read config file {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("config file {} is invalid: {detail}", path.display())]
    Parse { path: PathBuf, detail: String },

    #[error("config file {} contains a secret (`{key}`)", path.display())]
    SecretInConfig { path: PathBuf, key: String },
}

impl ConfigError {
    pub fn hint(&self) -> Option<String> {
        match self {
            Self::NotFound(_) => Some("Check the --config path or MDMSIGN_CONFIG.".into()),
            Self::Read { .. } => None,
            Self::Parse { .. } => {
                Some("See the README's \"Configuration\" section for the supported keys.".into())
            }
            Self::SecretInConfig { key, .. } => Some(format!(
                "Remove `{key}` from the file. Put the secret in an environment variable instead and name that variable with `p12_password_env`, or set MDMSIGN_P12_PASSWORD."
            )),
        }
    }
}

/// Parsed config file. Every field is optional.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub signing: SigningConfig,
    #[serde(default)]
    pub notarize: NotarizeConfig,
    #[serde(default)]
    pub package: PackageConfig,
    /// Where the config was loaded from, if anywhere.
    #[serde(skip)]
    pub path: Option<PathBuf>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SigningConfig {
    /// Keychain identity name or SHA-1 (macOS).
    pub identity: Option<String>,
    pub p12_path: Option<PathBuf>,
    /// Name of the environment variable holding the `.p12` password.
    pub p12_password_env: Option<String>,
    pub timestamp: Option<bool>,
    pub timestamp_url: Option<String>,
    pub backend: Option<Backend>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotarizeConfig {
    pub key_path: Option<PathBuf>,
    pub key_id: Option<String>,
    pub issuer_id: Option<String>,
    pub timeout_minutes: Option<u64>,
}

/// Settings for `mdmsign pkg`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageConfig {
    /// Prefix for default package identifiers, e.g. `com.example.pkg`; the
    /// app's bundle ID is appended.
    pub identifier_prefix: Option<String>,
    /// Folder apps install into. Defaults to `/Applications`.
    pub install_location: Option<PathBuf>,
}

impl Config {
    /// Loads the config file. An explicitly requested file (`explicit` or
    /// `$MDMSIGN_CONFIG`) must exist; the default location is optional.
    pub fn load(explicit: Option<&Path>, env: &dyn Env) -> Result<Self, ConfigError> {
        let requested = explicit
            .map(Path::to_path_buf)
            .or_else(|| env.var(crate::credentials::vars::CONFIG).map(PathBuf::from));
        let (path, required) = match requested {
            Some(path) => (expand_tilde(&path, env), true),
            None => match Self::default_path(env) {
                Some(path) => (path, false),
                None => return Ok(Self::default()),
            },
        };

        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return if required {
                    Err(ConfigError::NotFound(path))
                } else {
                    Ok(Self::default())
                };
            }
            Err(source) => return Err(ConfigError::Read { path, source }),
        };
        let mut config = Self::parse(&text, &path)?;
        config.signing.p12_path = config.signing.p12_path.map(|p| expand_tilde(&p, env));
        config.notarize.key_path = config.notarize.key_path.map(|p| expand_tilde(&p, env));
        config.path = Some(path);
        Ok(config)
    }

    /// Parses config text. `path` is only used in error messages.
    pub fn parse(text: &str, path: &Path) -> Result<Self, ConfigError> {
        let table: toml::Table = toml::from_str(text).map_err(|e| ConfigError::Parse {
            path: path.to_path_buf(),
            detail: e.message().to_string(),
        })?;
        if let Some(key) = find_secret_key(&table, "") {
            return Err(ConfigError::SecretInConfig {
                path: path.to_path_buf(),
                key,
            });
        }
        toml::from_str(text).map_err(|e| ConfigError::Parse {
            path: path.to_path_buf(),
            detail: e.message().to_string(),
        })
    }

    /// The default config location, if a home directory is known.
    pub fn default_path(env: &dyn Env) -> Option<PathBuf> {
        if let Some(xdg) = env.var("XDG_CONFIG_HOME") {
            return Some(PathBuf::from(xdg).join("mdmsign/config.toml"));
        }
        env.var("HOME")
            .map(|home| PathBuf::from(home).join(".config/mdmsign/config.toml"))
    }
}

fn find_secret_key(table: &toml::Table, prefix: &str) -> Option<String> {
    for (key, value) in table {
        let full = if prefix.is_empty() {
            key.clone()
        } else {
            format!("{prefix}.{key}")
        };
        let lower = key.to_ascii_lowercase();
        let names_env_var = lower.ends_with("_env");
        if !names_env_var
            && (lower.contains("password") || lower.contains("secret") || lower == "private_key")
        {
            return Some(full);
        }
        if let toml::Value::Table(inner) = value
            && let Some(found) = find_secret_key(inner, &full)
        {
            return Some(found);
        }
    }
    None
}

/// Expands a leading `~/` using `$HOME`.
pub fn expand_tilde(path: &Path, env: &dyn Env) -> PathBuf {
    match (path.strip_prefix("~"), env.var("HOME")) {
        (Ok(rest), Some(home)) => PathBuf::from(home).join(rest),
        _ => path.to_path_buf(),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn parses_full_config() {
        let config = Config::parse(
            r#"
            [signing]
            identity = "Developer ID Installer: Example (ABCDE12345)"
            p12_password_env = "MY_PASSWORD"
            backend = "native"
            [notarize]
            key_id = "ABC123"
            issuer_id = "uuid"
            [package]
            identifier_prefix = "com.example.pkg"
            "#,
            Path::new("c.toml"),
        )
        .unwrap();
        assert_eq!(config.signing.backend, Some(Backend::Native));
        assert_eq!(
            config.signing.p12_password_env.as_deref(),
            Some("MY_PASSWORD")
        );
        assert_eq!(config.notarize.key_id.as_deref(), Some("ABC123"));
        assert_eq!(
            config.package.identifier_prefix.as_deref(),
            Some("com.example.pkg")
        );
    }

    #[test]
    fn refuses_secrets() {
        let err = Config::parse(
            "[signing]\np12_password = \"hunter2\"\n",
            Path::new("c.toml"),
        )
        .unwrap_err();
        assert!(
            matches!(err, ConfigError::SecretInConfig { ref key, .. } if key == "signing.p12_password")
        );
        assert!(!err.to_string().contains("hunter2"));
    }

    #[test]
    fn rejects_unknown_keys() {
        let err = Config::parse("[signing]\nidentiy = \"x\"\n", Path::new("c.toml")).unwrap_err();
        assert!(err.to_string().contains("identiy"), "{err}");
    }

    #[test]
    fn missing_default_is_fine_but_explicit_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path().to_str().unwrap();
        assert!(Config::load(None, &env(&[("HOME", home)])).is_ok());
        let err = Config::load(Some(&dir.path().join("nope.toml")), &env(&[])).unwrap_err();
        assert!(matches!(err, ConfigError::NotFound(_)));
    }

    #[test]
    fn expands_tilde() {
        let env = env(&[("HOME", "/Users/admin")]);
        assert_eq!(
            expand_tilde(Path::new("~/a.p12"), &env),
            PathBuf::from("/Users/admin/a.p12")
        );
        assert_eq!(
            expand_tilde(Path::new("/x/a.p12"), &env),
            PathBuf::from("/x/a.p12")
        );
    }
}
