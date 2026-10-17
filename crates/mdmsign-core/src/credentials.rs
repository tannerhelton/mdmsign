//! Resolving credentials from flags, environment variables and the config
//! file, in that order of precedence.

use std::{collections::HashMap, path::PathBuf};

use base64::Engine;
use chrono::{DateTime, Utc};

use crate::{ArtifactKind, CertKind, Error, Secret, SigningIdentity, config::Config};

/// Environment variable names.
pub mod vars {
    /// Keychain identity name or SHA-1 (macOS).
    pub const IDENTITY: &str = "MDMSIGN_IDENTITY";
    /// Path to a `.p12` file.
    pub const P12_PATH: &str = "MDMSIGN_P12_PATH";
    /// Base64-encoded `.p12` contents, for CI secrets.
    pub const P12_BASE64: &str = "MDMSIGN_P12_BASE64";
    /// Password for the `.p12`.
    pub const P12_PASSWORD: &str = "MDMSIGN_P12_PASSWORD";
    /// Path to an App Store Connect API key (`AuthKey_XXXXXXXXXX.p8`).
    pub const ASC_KEY_PATH: &str = "MDMSIGN_ASC_KEY_PATH";
    /// Contents of an App Store Connect API key, for CI secrets.
    pub const ASC_KEY: &str = "MDMSIGN_ASC_KEY";
    pub const ASC_KEY_ID: &str = "MDMSIGN_ASC_KEY_ID";
    pub const ASC_ISSUER_ID: &str = "MDMSIGN_ASC_ISSUER_ID";
    /// Path to the config file.
    pub const CONFIG: &str = "MDMSIGN_CONFIG";
}

/// Source of environment variables; swappable in tests.
pub trait Env {
    /// Returns the variable's value, even if it's empty.
    fn raw_var(&self, key: &str) -> Option<String>;

    /// Returns the variable's value. Empty values count as unset.
    fn var(&self, key: &str) -> Option<String> {
        self.raw_var(key).filter(|v| !v.is_empty())
    }
}

/// The real process environment.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessEnv;

impl Env for ProcessEnv {
    fn raw_var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
}

impl Env for HashMap<String, String> {
    fn raw_var(&self, key: &str) -> Option<String> {
        self.get(key).cloned()
    }
}

/// Errors about credentials: which identity to use, loading it, and
/// whether it fits the job.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CredentialError {
    #[error("no signing identity was given")]
    NoIdentity,

    #[error("both a Keychain identity and a .p12 file were given")]
    ConflictingIdentity,

    #[error("no Keychain identity matches \"{query}\"")]
    IdentityNotFound {
        query: String,
        available: Vec<String>,
    },

    #[error("\"{query}\" matches more than one Keychain identity")]
    AmbiguousIdentity { query: String, matches: Vec<String> },

    #[error("the Keychain identity \"{name}\" isn't usable: {reason}")]
    IdentityInvalid { name: String, reason: String },

    #[error("Keychain identities are only available on macOS")]
    KeychainUnsupported,

    #[error("mdmsign is running as root, so your login Keychain isn't available")]
    RunningAsRoot,

    #[error("couldn't read the .p12 file {}: {source}", path.display())]
    P12Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("the password for {label} is wrong")]
    P12BadPassword { label: String },

    #[error("{label} isn't a usable .p12 file: {detail}")]
    P12Invalid { label: String, detail: String },

    #[error("{label} contains a certificate but no private key")]
    P12NoKey { label: String },

    #[error("{var} isn't valid base64")]
    InvalidBase64 { var: &'static str },

    #[error("no password was given for {label}")]
    MissingPassword { label: String },

    #[error("can't sign this {artifact} with \"{subject}\": {reason}")]
    WrongCertificateType {
        subject: String,
        found: CertKind,
        artifact: ArtifactKind,
        reason: String,
        fix: String,
    },

    #[error("the certificate \"{subject}\" expired on {}", not_after.format("%Y-%m-%d"))]
    CertificateExpired {
        subject: String,
        not_after: DateTime<Utc>,
    },

    #[error("the certificate \"{subject}\" isn't valid until {}", not_before.format("%Y-%m-%d"))]
    CertificateNotYetValid {
        subject: String,
        not_before: DateTime<Utc>,
    },

    #[error("missing App Store Connect {field}")]
    MissingAsc {
        field: &'static str,
        flag: &'static str,
        env: &'static str,
        /// The key under `[notarize]` in the config file.
        config_key: &'static str,
    },

    #[error("couldn't read the App Store Connect API key {}: {source}", path.display())]
    AscKeyRead {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("the App Store Connect API key from {label} is invalid: {detail}")]
    AscKeyInvalid { label: String, detail: String },
}

impl CredentialError {
    pub fn hint(&self) -> Option<String> {
        Some(match self {
            Self::NoIdentity => "Choose a signing identity with one of:\n  --identity \"Developer ID Installer: Your Org (TEAMID)\"   (macOS Keychain; run `mdmsign certs` to list them)\n  --p12 path/to/identity.p12                              (any platform; password from MDMSIGN_P12_PASSWORD or a prompt)\n  MDMSIGN_IDENTITY, MDMSIGN_P12_PATH or MDMSIGN_P12_BASE64 environment variables\n  `identity` or `p12_path` under [signing] in the config file".into(),
            Self::ConflictingIdentity => "Use either --identity (Keychain) or --p12, not both.".into(),
            Self::IdentityNotFound { available, .. } => {
                if available.is_empty() {
                    "No signing identities were found in your Keychain. Install your certificate together with its private key (double-click the .p12 or import it in Keychain Access), then run `mdmsign certs`.".into()
                } else {
                    format!(
                        "Use the full name or the SHA-1 fingerprint. Available identities:\n{}",
                        bullet_list(available)
                    )
                }
            }
            Self::AmbiguousIdentity { matches, .. } => format!(
                "Use the full name or the SHA-1 fingerprint (run `mdmsign certs`). Matches:\n{}",
                bullet_list(matches)
            ),
            Self::IdentityInvalid { .. } => "Run `mdmsign certs` to see which identities are valid. Expired or revoked certificates must be replaced at https://developer.apple.com/account/resources/certificates.".into(),
            Self::KeychainUnsupported => "Export the identity from Keychain Access on a Mac as a .p12 file and pass it with --p12 (or MDMSIGN_P12_PATH / MDMSIGN_P12_BASE64).".into(),
            Self::RunningAsRoot => "Run mdmsign without sudo.".into(),
            Self::P12Read { .. } => "Check the path to the .p12 file.".into(),
            Self::P12BadPassword { .. } => "Check MDMSIGN_P12_PASSWORD (or the variable named by `p12_password_env`). The password is the one you chose when exporting the .p12.".into(),
            Self::P12Invalid { .. } => "Export the identity again from Keychain Access (select the certificate and its private key, then File > Export Items > .p12).".into(),
            Self::P12NoKey { .. } => "In Keychain Access, expand the certificate to show its private key and export both together as a .p12. If the private key isn't on this Mac, it's on the Mac that created the certificate request, or you need a new certificate.".into(),
            Self::InvalidBase64 { var } => format!("Encode the .p12 with `base64 -i identity.p12 | pbcopy` and store the result in {var} without extra whitespace or quotes."),
            Self::MissingPassword { .. } => format!("Set {} or run mdmsign in a terminal so it can prompt for the password.", vars::P12_PASSWORD),
            Self::WrongCertificateType { fix, .. } => fix.clone(),
            Self::CertificateExpired { .. } | Self::CertificateNotYetValid { .. } => "Create a new certificate at https://developer.apple.com/account/resources/certificates and install it with its private key. Check your Mac's clock if the dates look wrong.".into(),
            Self::MissingAsc { flag, env, config_key, .. } => format!(
                "Pass {flag}, set {env}, or set `{config_key}` under [notarize] in the config file. Create an API key in App Store Connect under Users and Access > Integrations > App Store Connect API; the Issuer ID is shown above the key list."
            ),
            Self::AscKeyRead { .. } => "Check the path to the AuthKey_XXXXXXXXXX.p8 file. Apple only lets you download it once; if it's lost, revoke it and create a new key.".into(),
            Self::AscKeyInvalid { .. } => "Use the .p8 file downloaded from App Store Connect, unmodified. It starts with -----BEGIN PRIVATE KEY-----.".into(),
        })
    }
}

fn bullet_list(items: &[String]) -> String {
    items
        .iter()
        .map(|i| format!("  - {i}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Identity options given on the command line.
#[derive(Clone, Debug, Default)]
pub struct IdentityArgs {
    /// Keychain identity name or SHA-1.
    pub identity: Option<String>,
    /// Path to a `.p12` file.
    pub p12: Option<PathBuf>,
}

/// Which identity to load, before loading it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentitySpec {
    Keychain(String),
    P12File(PathBuf),
    /// Base64 `.p12` contents from [`vars::P12_BASE64`].
    P12Base64,
}

/// Picks the identity from flags, then environment, then config.
pub fn select_identity(
    args: &IdentityArgs,
    env: &dyn Env,
    config: &Config,
) -> Result<IdentitySpec, CredentialError> {
    let pick = |keychain: Option<String>,
                p12: Option<PathBuf>,
                base64: bool|
     -> Result<Option<IdentitySpec>, CredentialError> {
        match (keychain, p12, base64) {
            (Some(_), Some(_), _) | (Some(_), _, true) => Err(CredentialError::ConflictingIdentity),
            (Some(name), None, false) => Ok(Some(IdentitySpec::Keychain(name))),
            (None, Some(path), _) => Ok(Some(IdentitySpec::P12File(path))),
            (None, None, true) => Ok(Some(IdentitySpec::P12Base64)),
            (None, None, false) => Ok(None),
        }
    };
    if let Some(spec) = pick(args.identity.clone(), args.p12.clone(), false)? {
        return Ok(spec);
    }
    if let Some(spec) = pick(
        env.var(vars::IDENTITY),
        env.var(vars::P12_PATH).map(PathBuf::from),
        env.var(vars::P12_BASE64).is_some(),
    )? {
        return Ok(spec);
    }
    pick(
        config.signing.identity.clone(),
        config.signing.p12_path.clone(),
        false,
    )?
    .ok_or(CredentialError::NoIdentity)
}

/// Prompts for a secret. Returns `None` when prompting isn't possible
/// (no terminal), which becomes [`CredentialError::MissingPassword`].
pub type Prompt<'a> = &'a mut dyn FnMut(&str) -> Option<Secret>;

/// Loads the selected identity.
pub fn load_identity(
    spec: &IdentitySpec,
    env: &dyn Env,
    config: &Config,
    prompt: Prompt<'_>,
) -> Result<SigningIdentity, Error> {
    let (data, label) = match spec {
        IdentitySpec::Keychain(query) => return crate::keychain::load_identity(query),
        IdentitySpec::P12File(path) => {
            let data = std::fs::read(path).map_err(|source| CredentialError::P12Read {
                path: path.clone(),
                source,
            })?;
            (data, path.display().to_string())
        }
        IdentitySpec::P12Base64 => {
            let encoded = env.var(vars::P12_BASE64).unwrap_or_default();
            let cleaned: String = encoded.chars().filter(|c| !c.is_whitespace()).collect();
            let data = base64::engine::general_purpose::STANDARD
                .decode(cleaned)
                .map_err(|_| CredentialError::InvalidBase64 {
                    var: vars::P12_BASE64,
                })?;
            (data, vars::P12_BASE64.to_string())
        }
    };
    let password = p12_password(env, config)
        .or_else(|| prompt(&format!("Password for {label}: ")))
        .ok_or_else(|| CredentialError::MissingPassword {
            label: label.clone(),
        })?;
    Ok(SigningIdentity::from_p12(&data, &password, label)?)
}

fn p12_password(env: &dyn Env, config: &Config) -> Option<Secret> {
    // Empty passwords are legitimate for .p12 files, so read raw values.
    if let Some(value) = env.raw_var(vars::P12_PASSWORD) {
        return Some(Secret::new(value));
    }
    let name = config.signing.p12_password_env.as_deref()?;
    env.raw_var(name).map(Secret::new)
}

/// App Store Connect API key options given on the command line.
#[derive(Clone, Debug, Default)]
pub struct AscArgs {
    pub key_path: Option<PathBuf>,
    pub key_id: Option<String>,
    pub issuer_id: Option<String>,
}

/// A resolved App Store Connect API key.
#[derive(Clone, Debug)]
pub struct AscCredentials {
    pub key_id: String,
    pub issuer_id: String,
    /// PEM contents of the `.p8` file.
    pub private_key_pem: Secret,
    /// Where the key came from, for messages.
    pub source: String,
}

/// Resolves the App Store Connect API key from flags, then environment,
/// then config. The key ID is inferred from an `AuthKey_<ID>.p8` file name
/// when not given.
pub fn load_asc_credentials(
    args: &AscArgs,
    env: &dyn Env,
    config: &Config,
) -> Result<AscCredentials, CredentialError> {
    // Precedence: --key, MDMSIGN_ASC_KEY_PATH, MDMSIGN_ASC_KEY (contents), config.
    let env_pem = env.var(vars::ASC_KEY);
    let key_path = args
        .key_path
        .clone()
        .or_else(|| env.var(vars::ASC_KEY_PATH).map(PathBuf::from))
        .or_else(|| {
            if env_pem.is_none() {
                config.notarize.key_path.clone()
            } else {
                None
            }
        });

    let (pem, source) = match (&key_path, env_pem) {
        (Some(path), _) => {
            let pem =
                std::fs::read_to_string(path).map_err(|source| CredentialError::AscKeyRead {
                    path: path.clone(),
                    source,
                })?;
            (pem, path.display().to_string())
        }
        (None, Some(pem)) => (pem, vars::ASC_KEY.to_string()),
        (None, None) => {
            return Err(CredentialError::MissingAsc {
                field: "API key",
                flag: "--key",
                env: vars::ASC_KEY_PATH,
                config_key: "key_path",
            });
        }
    };
    if !pem.contains("-----BEGIN PRIVATE KEY-----") {
        return Err(CredentialError::AscKeyInvalid {
            label: source,
            detail: "it isn't a PEM private key".into(),
        });
    }

    let inferred_id = key_path
        .as_ref()
        .and_then(|p| p.file_stem())
        .and_then(|s| s.to_str())
        .and_then(|s| s.strip_prefix("AuthKey_"))
        .map(str::to_string);
    let key_id = args
        .key_id
        .clone()
        .or_else(|| env.var(vars::ASC_KEY_ID))
        .or_else(|| config.notarize.key_id.clone())
        .or(inferred_id)
        .ok_or(CredentialError::MissingAsc {
            field: "key ID",
            flag: "--key-id",
            env: vars::ASC_KEY_ID,
            config_key: "key_id",
        })?;
    let issuer_id = args
        .issuer_id
        .clone()
        .or_else(|| env.var(vars::ASC_ISSUER_ID))
        .or_else(|| config.notarize.issuer_id.clone())
        .ok_or(CredentialError::MissingAsc {
            field: "issuer ID",
            flag: "--issuer",
            env: vars::ASC_ISSUER_ID,
            config_key: "issuer_id",
        })?;

    Ok(AscCredentials {
        key_id,
        issuer_id,
        private_key_pem: Secret::new(pem),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::TestIdentity;

    fn env(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn flags_beat_env_beat_config() {
        let mut config = Config::default();
        config.signing.identity = Some("from config".into());
        let env_vars = env(&[(vars::P12_PATH, "/env.p12")]);

        let args = IdentityArgs {
            identity: Some("from flag".into()),
            p12: None,
        };
        assert_eq!(
            select_identity(&args, &env_vars, &config).unwrap(),
            IdentitySpec::Keychain("from flag".into())
        );

        let none = IdentityArgs::default();
        assert_eq!(
            select_identity(&none, &env_vars, &config).unwrap(),
            IdentitySpec::P12File("/env.p12".into())
        );
        assert_eq!(
            select_identity(&none, &env(&[]), &config).unwrap(),
            IdentitySpec::Keychain("from config".into())
        );
        assert!(matches!(
            select_identity(&none, &env(&[]), &Config::default()),
            Err(CredentialError::NoIdentity)
        ));
    }

    #[test]
    fn conflicting_sources_at_same_level() {
        let args = IdentityArgs {
            identity: Some("x".into()),
            p12: Some("y.p12".into()),
        };
        assert!(matches!(
            select_identity(&args, &env(&[]), &Config::default()),
            Err(CredentialError::ConflictingIdentity)
        ));
    }

    #[test]
    fn loads_base64_p12_from_env() {
        let test = TestIdentity::generate(CertKind::DeveloperIdInstaller);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&test.p12);
        let env_vars = env(&[(vars::P12_BASE64, &encoded)]);
        let mut prompt = |_: &str| Some(Secret::new(test.password.clone()));
        let identity = load_identity(
            &IdentitySpec::P12Base64,
            &env_vars,
            &Config::default(),
            &mut prompt,
        )
        .unwrap();
        assert_eq!(identity.kind(), CertKind::DeveloperIdInstaller);
        assert_eq!(identity.source(), vars::P12_BASE64);
    }

    #[test]
    fn missing_password_without_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let test = TestIdentity::generate(CertKind::DeveloperIdInstaller);
        let path = test.write_p12(dir.path());
        let mut prompt = |_: &str| None;
        let err = load_identity(
            &IdentitySpec::P12File(path),
            &env(&[]),
            &Config::default(),
            &mut prompt,
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                Error::Credential(CredentialError::MissingPassword { .. })
            ),
            "{err:?}"
        );
    }

    #[test]
    fn legacy_p12_also_loads() {
        let test = TestIdentity::generate(CertKind::DeveloperIdInstaller);
        let identity =
            SigningIdentity::from_p12(&test.p12_legacy, &Secret::new(&test.password), "legacy.p12")
                .unwrap();
        assert_eq!(identity.kind(), CertKind::DeveloperIdInstaller);
    }

    #[test]
    fn asc_key_id_inferred_from_file_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("AuthKey_ABC123DEFG.p8");
        std::fs::write(
            &path,
            "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
        )
        .unwrap();
        let args = AscArgs {
            key_path: Some(path),
            issuer_id: Some("issuer".into()),
            ..Default::default()
        };
        let creds = load_asc_credentials(&args, &env(&[]), &Config::default()).unwrap();
        assert_eq!(creds.key_id, "ABC123DEFG");
        assert!(!format!("{creds:?}").contains("abc"));
    }

    #[test]
    fn asc_missing_issuer_has_hint() {
        let env_vars = env(&[
            (vars::ASC_KEY, "-----BEGIN PRIVATE KEY-----\nx"),
            (vars::ASC_KEY_ID, "K"),
        ]);
        let err =
            load_asc_credentials(&AscArgs::default(), &env_vars, &Config::default()).unwrap_err();
        assert!(err.to_string().contains("issuer ID"));
        let hint = err.hint().unwrap();
        assert!(hint.contains("MDMSIGN_ASC_ISSUER_ID"));
        assert!(hint.contains("`issuer_id` under [notarize]"));
    }
}
