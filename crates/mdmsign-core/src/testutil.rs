//! Throwaway test certificates, generated at test time.
//!
//! Certificates are self-signed but carry the same Apple extensions as the
//! real thing, so certificate-type checks behave as they would with real
//! Apple-issued certificates. Chain-of-trust checks will (correctly) fail.

use std::path::{Path, PathBuf};

use apple_codesign::create_self_signed_code_signing_certificate;
use p12_keystore::{
    Certificate, EncryptionAlgorithm, KeyStore, KeyStoreEntry, MacAlgorithm, PrivateKeyChain,
};
use x509_certificate::{CapturedX509Certificate, KeyAlgorithm};

use crate::CertKind;

/// Team ID used for all generated certificates.
pub const TEAM_ID: &str = "MDMSIGNT01";

/// A generated certificate and its `.p12` export.
#[derive(Debug)]
pub struct TestIdentity {
    pub certificate: CapturedX509Certificate,
    /// `.p12` bytes in the modern format (AES-256, HMAC-SHA256).
    pub p12: Vec<u8>,
    /// `.p12` bytes in the legacy format (3DES, HMAC-SHA1).
    pub p12_legacy: Vec<u8>,
    pub password: String,
    pub common_name: String,
}

impl TestIdentity {
    /// Generates a self-signed RSA certificate shaped like `kind`.
    ///
    /// Panics for [`CertKind::Other`], which has no Apple profile.
    pub fn generate(kind: CertKind) -> Self {
        let profile = kind
            .to_apple_profile()
            .expect("test certificates must be an Apple certificate type");
        let (certificate, key) = create_self_signed_code_signing_certificate(
            KeyAlgorithm::Rsa,
            profile,
            TEAM_ID,
            "mdmsign test",
            "US",
            chrono::Duration::days(2),
        )
        .expect("generating a test certificate");
        let common_name = certificate.subject_common_name().unwrap_or_default();
        let password = "mdmsign-test-password".to_string();

        let pkcs8 = key.to_pkcs8_one_asymmetric_key_der();
        let cert_der = certificate.encode_der().expect("encoding test certificate");
        let mut store = KeyStore::new();
        store.add_entry(
            "mdmsign-test",
            KeyStoreEntry::PrivateKeyChain(PrivateKeyChain::new(
                pkcs8.as_slice(),
                [1u8; 20],
                [Certificate::from_der(&cert_der).expect("re-parsing test certificate")],
            )),
        );
        let p12 = store
            .writer(&password)
            .write()
            .expect("writing modern .p12");
        let p12_legacy = store
            .writer(&password)
            .encryption_algorithm(EncryptionAlgorithm::PbeWithShaAnd3KeyTripleDesCbc)
            .mac_algorithm(MacAlgorithm::HmacSha1)
            .write()
            .expect("writing legacy .p12");

        Self {
            certificate,
            p12,
            p12_legacy,
            password,
            common_name,
        }
    }

    /// Writes the modern `.p12` into `dir` and returns its path.
    pub fn write_p12(&self, dir: &Path) -> PathBuf {
        let path = dir.join("identity.p12");
        std::fs::write(&path, &self.p12).expect("writing test .p12");
        path
    }
}

/// A minimal, valid, unsigned configuration profile.
pub const SAMPLE_PROFILE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>PayloadContent</key>
	<array/>
	<key>PayloadDisplayName</key>
	<string>mdmsign test profile</string>
	<key>PayloadIdentifier</key>
	<string>com.example.mdmsign.test</string>
	<key>PayloadType</key>
	<string>Configuration</string>
	<key>PayloadUUID</key>
	<string>9A3C1A0E-4C1B-4F0B-9D6F-2C1E2B1F0A01</string>
	<key>PayloadVersion</key>
	<integer>1</integer>
</dict>
</plist>
"#;

/// Writes [`SAMPLE_PROFILE`] into `dir` and returns its path.
pub fn write_sample_profile(dir: &Path) -> PathBuf {
    let path = dir.join("sample.mobileconfig");
    std::fs::write(&path, SAMPLE_PROFILE).expect("writing sample profile");
    path
}

/// Path to a committed test fixture in `crates/mdmsign-core/tests/fixtures`.
///
/// `unsigned.pkg` is a tiny unsigned flat package built with `pkgbuild`; see
/// `tests/fixtures/README.md` for how to regenerate it.
pub fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

/// Copies a fixture into `dir` and returns the copy's path.
pub fn copy_fixture(name: &str, dir: &Path) -> PathBuf {
    let dest = dir.join(name);
    std::fs::copy(fixture(name), &dest).expect("copying fixture");
    dest
}
