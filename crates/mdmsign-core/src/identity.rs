//! Signing identities (certificate + private key) and certificate types.

use apple_codesign::{AppleCertificate, CertificateProfile, cryptography::InMemoryPrivateKey};
use chrono::{DateTime, Utc};
use serde::Serialize;
use x509_certificate::{CapturedX509Certificate, Sign};

use crate::{ArtifactKind, Secret, credentials::CredentialError};

/// The type of an Apple-issued signing certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum CertKind {
    /// Signs installer packages distributed outside the Mac App Store.
    DeveloperIdInstaller,
    /// Signs apps, binaries and disk images distributed outside the Mac App Store.
    DeveloperIdApplication,
    /// Signs installer packages submitted to the Mac App Store
    /// ("3rd Party Mac Developer Installer").
    MacInstallerDistribution,
    /// Signs apps submitted to the App Store.
    AppleDistribution,
    /// Signs apps during development.
    AppleDevelopment,
    /// Anything else, such as a certificate from your own CA.
    Other,
}

/// Whether a certificate is suitable for signing a kind of file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Suitability {
    Suitable,
    /// Works, but there's a better choice.
    Discouraged {
        reason: String,
    },
    /// Won't produce a file Macs accept.
    Unsuitable {
        reason: String,
        fix: String,
    },
}

const GET_INSTALLER_CERT: &str = "Create a Developer ID Installer certificate at https://developer.apple.com/account/resources/certificates (only the team's Account Holder can), install it with its private key, then run `mdmsign certs` to confirm it shows up.";

impl CertKind {
    /// Classifies a certificate from its Apple extensions, falling back to
    /// the common-name prefix Apple uses for each type.
    pub fn classify(cert: &CapturedX509Certificate) -> Self {
        match cert.apple_guess_profile() {
            Some(CertificateProfile::DeveloperIdInstaller) => return Self::DeveloperIdInstaller,
            Some(CertificateProfile::DeveloperIdApplication) => {
                return Self::DeveloperIdApplication;
            }
            Some(CertificateProfile::MacInstallerDistribution) => {
                return Self::MacInstallerDistribution;
            }
            Some(CertificateProfile::AppleDistribution) => return Self::AppleDistribution,
            Some(CertificateProfile::AppleDevelopment) => return Self::AppleDevelopment,
            None => {}
        }
        cert.subject_common_name()
            .map(|cn| Self::from_common_name(&cn))
            .unwrap_or(Self::Other)
    }

    /// Classifies from a certificate common name such as
    /// `Developer ID Installer: Example Corp (ABCDE12345)`.
    pub fn from_common_name(cn: &str) -> Self {
        const PREFIXES: &[(&str, CertKind)] = &[
            ("Developer ID Installer:", CertKind::DeveloperIdInstaller),
            (
                "Developer ID Application:",
                CertKind::DeveloperIdApplication,
            ),
            (
                "3rd Party Mac Developer Installer:",
                CertKind::MacInstallerDistribution,
            ),
            (
                "Mac Installer Distribution:",
                CertKind::MacInstallerDistribution,
            ),
            (
                "3rd Party Mac Developer Application:",
                CertKind::AppleDistribution,
            ),
            ("Apple Distribution:", CertKind::AppleDistribution),
            ("Apple Development:", CertKind::AppleDevelopment),
            ("Mac Developer:", CertKind::AppleDevelopment),
        ];
        PREFIXES
            .iter()
            .find(|(prefix, _)| cn.starts_with(prefix))
            .map(|(_, kind)| *kind)
            .unwrap_or(Self::Other)
    }

    /// The name Apple uses for this certificate type.
    pub fn display_name(self) -> &'static str {
        match self {
            Self::DeveloperIdInstaller => "Developer ID Installer",
            Self::DeveloperIdApplication => "Developer ID Application",
            Self::MacInstallerDistribution => "Mac Installer Distribution",
            Self::AppleDistribution => "Apple Distribution",
            Self::AppleDevelopment => "Apple Development",
            Self::Other => "non-Apple certificate",
        }
    }

    /// Whether this certificate type can sign `kind` for MDM deployment.
    pub fn suitability(self, kind: ArtifactKind) -> Suitability {
        match kind {
            ArtifactKind::FlatPackage => match self {
                Self::DeveloperIdInstaller => Suitability::Suitable,
                Self::DeveloperIdApplication => Suitability::Unsuitable {
                    reason: "a Developer ID Application certificate can't sign .pkg installers; you need a Developer ID Installer certificate".into(),
                    fix: GET_INSTALLER_CERT.into(),
                },
                Self::MacInstallerDistribution => Suitability::Unsuitable {
                    reason: "a Mac Installer Distribution certificate is only for Mac App Store submissions; Macs won't trust packages signed with it when installed by an MDM".into(),
                    fix: GET_INSTALLER_CERT.into(),
                },
                Self::AppleDistribution | Self::AppleDevelopment => Suitability::Unsuitable {
                    reason: format!(
                        "an {} certificate can't sign .pkg installers; you need a Developer ID Installer certificate",
                        self.display_name()
                    ),
                    fix: GET_INSTALLER_CERT.into(),
                },
                Self::Other => Suitability::Unsuitable {
                    reason: "this isn't an Apple Developer ID Installer certificate, so Macs won't trust the package".into(),
                    fix: GET_INSTALLER_CERT.into(),
                },
            },
            // Profiles can be signed by any certificate. macOS shows them as
            // "Verified" when the chain leads to a trusted root, which every
            // Apple-issued type does.
            ArtifactKind::ConfigurationProfile => match self {
                Self::Other => Suitability::Discouraged {
                    reason: "profiles signed with a certificate that doesn't chain to a trusted root show as \"Not Verified\" on Macs".into(),
                },
                _ => Suitability::Suitable,
            },
        }
    }

    /// Maps to the apple-codesign profile, if there is one.
    pub fn to_apple_profile(self) -> Option<CertificateProfile> {
        Some(match self {
            Self::DeveloperIdInstaller => CertificateProfile::DeveloperIdInstaller,
            Self::DeveloperIdApplication => CertificateProfile::DeveloperIdApplication,
            Self::MacInstallerDistribution => CertificateProfile::MacInstallerDistribution,
            Self::AppleDistribution => CertificateProfile::AppleDistribution,
            Self::AppleDevelopment => CertificateProfile::AppleDevelopment,
            Self::Other => return None,
        })
    }
}

impl std::fmt::Display for CertKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.display_name())
    }
}

/// Where the private key for a [`SigningIdentity`] lives.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum KeySource {
    /// Loaded into memory from a `.p12` file.
    InMemory(InMemoryPrivateKey),
    /// Stays in the macOS Keychain; only Apple's tools can use it without a
    /// Keychain prompt.
    Keychain {
        /// Uppercase hex SHA-1 fingerprint of the certificate.
        sha1: String,
    },
}

/// A certificate, its private key, and any intermediate certificates.
#[derive(Clone, Debug)]
pub struct SigningIdentity {
    certificate: CapturedX509Certificate,
    chain: Vec<CapturedX509Certificate>,
    key: KeySource,
    source: String,
}

impl SigningIdentity {
    /// Loads an identity from `.p12` (PKCS #12) data.
    ///
    /// Both the legacy format (3DES / SHA-1, still the macOS Keychain Access
    /// default) and the modern format (AES / SHA-256, the OpenSSL 3 default)
    /// are supported. `label` describes where the data came from and is
    /// used in messages.
    pub fn from_p12(
        data: &[u8],
        password: &Secret,
        label: impl Into<String>,
    ) -> Result<Self, CredentialError> {
        let label = label.into();
        let store =
            p12_keystore::KeyStore::from_pkcs12(data, password.expose()).map_err(|e| match e {
                p12_keystore::error::Error::MacError(_) => CredentialError::P12BadPassword {
                    label: label.clone(),
                },
                other => CredentialError::P12Invalid {
                    label: label.clone(),
                    detail: other.to_string(),
                },
            })?;
        let (_, key_chain) =
            store
                .private_key_chain()
                .ok_or_else(|| CredentialError::P12NoKey {
                    label: label.clone(),
                })?;

        let key = InMemoryPrivateKey::from_pkcs8_der(key_chain.key()).map_err(|e| {
            CredentialError::P12Invalid {
                label: label.clone(),
                detail: format!("unsupported private key: {e}"),
            }
        })?;

        let mut certs = key_chain
            .chain()
            .iter()
            .map(|c| CapturedX509Certificate::from_der(c.as_der().to_vec()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| CredentialError::P12Invalid {
                label: label.clone(),
                detail: format!("unreadable certificate: {e}"),
            })?;

        let public_key = key.public_key_data();
        let leaf_index = certs
            .iter()
            .position(|c| c.public_key_data() == public_key)
            .ok_or_else(|| CredentialError::P12Invalid {
                label: label.clone(),
                detail: "no certificate in the file matches its private key".into(),
            })?;
        let certificate = certs.remove(leaf_index);

        Ok(Self {
            certificate,
            chain: certs,
            key: KeySource::InMemory(key),
            source: label,
        })
    }

    /// An identity whose key stays in the macOS Keychain.
    pub fn from_keychain(certificate: CapturedX509Certificate, sha1: String) -> Self {
        Self {
            certificate,
            chain: Vec::new(),
            key: KeySource::Keychain { sha1 },
            source: "macOS Keychain".into(),
        }
    }

    pub fn certificate(&self) -> &CapturedX509Certificate {
        &self.certificate
    }

    /// Intermediate certificates supplied alongside the signing certificate.
    pub fn chain(&self) -> &[CapturedX509Certificate] {
        &self.chain
    }

    pub fn key(&self) -> &KeySource {
        &self.key
    }

    /// The in-memory private key, if this identity came from a `.p12`.
    pub fn private_key(&self) -> Option<&InMemoryPrivateKey> {
        match &self.key {
            KeySource::InMemory(key) => Some(key),
            KeySource::Keychain { .. } => None,
        }
    }

    pub fn is_keychain(&self) -> bool {
        matches!(self.key, KeySource::Keychain { .. })
    }

    /// Where the identity was loaded from, for messages.
    pub fn source(&self) -> &str {
        &self.source
    }

    pub fn kind(&self) -> CertKind {
        CertKind::classify(&self.certificate)
    }

    pub fn common_name(&self) -> String {
        self.certificate
            .subject_common_name()
            .unwrap_or_else(|| "(certificate without a common name)".into())
    }

    pub fn team_id(&self) -> Option<String> {
        self.certificate.apple_team_id()
    }

    /// Uppercase hex SHA-1 fingerprint, the form `security find-identity` prints.
    pub fn sha1_fingerprint(&self) -> String {
        sha1_fingerprint(&self.certificate)
    }

    pub fn not_after(&self) -> DateTime<Utc> {
        self.certificate.validity_not_after()
    }

    /// Checks that this identity can sign `kind` right now: correct
    /// certificate type, and within its validity period.
    pub fn check_for(
        &self,
        kind: ArtifactKind,
        now: DateTime<Utc>,
    ) -> Result<Option<String>, CredentialError> {
        let subject = self.common_name();
        if now > self.certificate.validity_not_after() {
            return Err(CredentialError::CertificateExpired {
                subject,
                not_after: self.certificate.validity_not_after(),
            });
        }
        if now < self.certificate.validity_not_before() {
            return Err(CredentialError::CertificateNotYetValid {
                subject,
                not_before: self.certificate.validity_not_before(),
            });
        }
        match self.kind().suitability(kind) {
            Suitability::Suitable => Ok(None),
            Suitability::Discouraged { reason } => Ok(Some(reason)),
            Suitability::Unsuitable { reason, fix } => Err(CredentialError::WrongCertificateType {
                subject,
                found: self.kind(),
                artifact: kind,
                reason,
                fix,
            }),
        }
    }
}

/// Uppercase hex SHA-1 fingerprint of a certificate.
pub fn sha1_fingerprint(cert: &CapturedX509Certificate) -> String {
    cert.sha1_fingerprint()
        .map(|d| hex::encode_upper(d.as_ref()))
        .unwrap_or_default()
}

/// Uppercase hex SHA-256 fingerprint of a certificate.
pub fn sha256_fingerprint(cert: &CapturedX509Certificate) -> String {
    cert.sha256_fingerprint()
        .map(|d| hex::encode_upper(d.as_ref()))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;

    #[test]
    fn classifies_by_common_name() {
        assert_eq!(
            CertKind::from_common_name("Developer ID Installer: Example (ABCDE12345)"),
            CertKind::DeveloperIdInstaller
        );
        assert_eq!(
            CertKind::from_common_name("3rd Party Mac Developer Installer: Example (ABCDE12345)"),
            CertKind::MacInstallerDistribution
        );
        assert_eq!(CertKind::from_common_name("example.com"), CertKind::Other);
    }

    #[test]
    fn pkg_needs_installer_cert() {
        assert_eq!(
            CertKind::DeveloperIdInstaller.suitability(ArtifactKind::FlatPackage),
            Suitability::Suitable
        );
        let Suitability::Unsuitable { reason, .. } =
            CertKind::DeveloperIdApplication.suitability(ArtifactKind::FlatPackage)
        else {
            panic!("application cert must not sign pkg");
        };
        assert!(reason.contains("you need a Developer ID Installer"));
        assert!(matches!(
            CertKind::MacInstallerDistribution.suitability(ArtifactKind::FlatPackage),
            Suitability::Unsuitable { .. }
        ));
    }

    #[test]
    fn profile_accepts_apple_certs() {
        for kind in [
            CertKind::DeveloperIdApplication,
            CertKind::DeveloperIdInstaller,
            CertKind::AppleDevelopment,
        ] {
            assert_eq!(
                kind.suitability(ArtifactKind::ConfigurationProfile),
                Suitability::Suitable
            );
        }
    }

    #[test]
    fn loads_generated_p12_and_classifies() {
        for kind in [
            CertKind::DeveloperIdInstaller,
            CertKind::DeveloperIdApplication,
        ] {
            let test = testutil::TestIdentity::generate(kind);
            let identity =
                SigningIdentity::from_p12(&test.p12, &Secret::new(&test.password), "test.p12")
                    .unwrap();
            assert_eq!(identity.kind(), kind);
            assert_eq!(identity.team_id().as_deref(), Some(testutil::TEAM_ID));
            assert_eq!(identity.sha1_fingerprint().len(), 40);
            assert!(identity.private_key().is_some());
        }
    }

    #[test]
    fn wrong_password_is_reported_clearly() {
        let test = testutil::TestIdentity::generate(CertKind::DeveloperIdInstaller);
        let err =
            SigningIdentity::from_p12(&test.p12, &Secret::new("wrong"), "test.p12").unwrap_err();
        assert!(
            matches!(err, CredentialError::P12BadPassword { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn check_for_rejects_wrong_type() {
        let test = testutil::TestIdentity::generate(CertKind::DeveloperIdApplication);
        let identity =
            SigningIdentity::from_p12(&test.p12, &Secret::new(&test.password), "test.p12").unwrap();
        let err = identity
            .check_for(ArtifactKind::FlatPackage, Utc::now())
            .unwrap_err();
        assert!(err.to_string().contains("Developer ID Installer"), "{err}");
        assert!(
            identity
                .check_for(ArtifactKind::ConfigurationProfile, Utc::now())
                .is_ok()
        );
    }
}
