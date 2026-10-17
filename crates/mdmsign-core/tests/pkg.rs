//! Signing and verifying flat installer packages end to end.
//!
//! Tests that need a real Apple-issued identity or the network are
//! `#[ignore]`d and read their inputs from environment variables:
//!
//! - `MDMSIGN_TEST_SIGNED_PKG`: any package signed by a real Developer ID
//!   Installer certificate (e.g. a vendor download).
//! - `MDMSIGN_TEST_P12_PATH` + `MDMSIGN_TEST_P12_PASSWORD`: a real Developer
//!   ID Installer `.p12`.
//! - `MDMSIGN_TEST_KEYCHAIN_IDENTITY`: the name or SHA-1 of a Developer ID
//!   Installer identity in the login Keychain (macOS; may show a Keychain
//!   prompt).
//! - `MDMSIGN_TEST_NETWORK=1`: allow tests that contact Apple.
//!
//! Run them with `cargo test -p mdmsign-core --all-features --test pkg -- --ignored`.

#![cfg(feature = "test-util")]

use std::path::{Path, PathBuf};

use mdmsign_core::{
    CertKind, Error, Secret, SigningIdentity,
    sign::{self, Output, SignOptions, pkg::PkgError},
    testutil::{self, TestIdentity},
    verify::{self, CheckId, Report, Status, VerifyOptions},
};

fn identity(kind: CertKind) -> SigningIdentity {
    let test = TestIdentity::generate(kind);
    SigningIdentity::from_p12(&test.p12, &Secret::new(&test.password), "test.p12").unwrap()
}

fn no_timestamp() -> SignOptions {
    SignOptions {
        timestamp: false,
        ..SignOptions::default()
    }
}

fn offline() -> VerifyOptions {
    VerifyOptions {
        offline: true,
        system_checks: false,
        ..VerifyOptions::default()
    }
}

fn status(report: &Report, id: CheckId) -> Status {
    report
        .check(id)
        .unwrap_or_else(|| panic!("missing {id:?} check in {report:#?}"))
        .status
}

/// Signs a fresh copy of the fixture into `dir` and returns its path.
fn signed_fixture(dir: &Path, identity: &SigningIdentity) -> PathBuf {
    let input = testutil::copy_fixture("unsigned.pkg", dir);
    sign::sign_file(&input, &Output::Default, identity, &no_timestamp())
        .unwrap()
        .output
}

#[test]
fn sign_then_verify_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let input = testutil::copy_fixture("unsigned.pkg", dir.path());
    let identity = identity(CertKind::DeveloperIdInstaller);

    let outcome = sign::sign_file(&input, &Output::Default, &identity, &no_timestamp()).unwrap();
    assert_eq!(outcome.output, dir.path().join("unsigned-signed.pkg"));
    assert_eq!(outcome.backend, "apple-codesign");
    assert!(!outcome.timestamped);
    assert!(outcome.warnings.is_empty(), "{:?}", outcome.warnings);
    assert!(
        !sign::is_signed(&input, mdmsign_core::ArtifactKind::FlatPackage).unwrap(),
        "the input must not be modified"
    );
    // Nothing is left behind in the staging directory.
    let leftovers: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(leftovers.len(), 2, "{leftovers:?}");

    let report = verify::verify_file(&outcome.output, &offline()).unwrap();
    assert_eq!(status(&report, CheckId::Format), Status::Pass);
    assert_eq!(status(&report, CheckId::Signed), Status::Pass);
    assert_eq!(status(&report, CheckId::SignatureValid), Status::Pass);
    assert_eq!(status(&report, CheckId::CertificateType), Status::Pass);
    assert_eq!(status(&report, CheckId::CertificateValidity), Status::Pass);
    // Self-signed test certificates don't chain to Apple.
    assert_eq!(status(&report, CheckId::CertificateChain), Status::Fail);
    assert_eq!(status(&report, CheckId::Timestamp), Status::Warn);
    assert_eq!(status(&report, CheckId::Notarization), Status::Skip);
    assert_eq!(status(&report, CheckId::Staple), Status::Warn);
    assert!(report.check(CheckId::Gatekeeper).is_none());
    assert!(!report.mdm_ready);

    let signer = report.signer.as_ref().unwrap();
    assert_eq!(signer.common_name, identity.common_name());
    assert_eq!(signer.cert_kind, CertKind::DeveloperIdInstaller);
    assert_eq!(signer.sha1, identity.sha1_fingerprint());

    let timestamp = report.check(CheckId::Timestamp).unwrap();
    assert!(timestamp.fix.as_deref().unwrap().contains("--no-timestamp"));
    let chain = report.check(CheckId::CertificateChain).unwrap();
    assert!(chain.summary.contains("isn't issued by Apple"));
}

/// The signer certificate comes out of the CMS x-signature, which is parsed
/// in BER mode; fingerprinting such a certificate used to panic in bcder.
#[test]
fn signer_info_from_cms_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let identity = identity(CertKind::DeveloperIdInstaller);
    let signed = signed_fixture(dir.path(), &identity);

    let report = verify::verify_file(&signed, &offline()).unwrap();
    let signer = report.signer.expect("signer info");
    assert_eq!(signer.sha1, identity.sha1_fingerprint());
    assert_eq!(signer.sha256.len(), 64);
    assert_eq!(signer.team_id.as_deref(), Some(testutil::TEAM_ID));
    assert_eq!(signer.cert_kind, CertKind::DeveloperIdInstaller);
}

#[test]
fn application_certificate_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let input = testutil::copy_fixture("unsigned.pkg", dir.path());
    let identity = identity(CertKind::DeveloperIdApplication);

    let err = sign::sign_file(&input, &Output::Default, &identity, &no_timestamp()).unwrap_err();
    assert!(matches!(err, Error::Credential(_)), "{err:?}");
    assert!(
        err.to_string()
            .contains("you need a Developer ID Installer"),
        "{err}"
    );
    assert!(err.hint().unwrap().contains("Developer ID Installer"));
    assert!(!dir.path().join("unsigned-signed.pkg").exists());
}

#[test]
fn signed_input_needs_resign() {
    let dir = tempfile::tempdir().unwrap();
    let identity = identity(CertKind::DeveloperIdInstaller);
    let signed = signed_fixture(dir.path(), &identity);

    let err = sign::sign_file(&signed, &Output::InPlace, &identity, &no_timestamp()).unwrap_err();
    assert!(matches!(err, Error::AlreadySigned { .. }), "{err:?}");
    assert!(err.hint().unwrap().contains("--resign"));
}

#[test]
fn resign_replaces_the_signature() {
    let dir = tempfile::tempdir().unwrap();
    let first = identity(CertKind::DeveloperIdInstaller);
    let second = identity(CertKind::DeveloperIdInstaller);
    let signed = signed_fixture(dir.path(), &first);

    let options = SignOptions {
        resign: true,
        ..no_timestamp()
    };
    let outcome = sign::sign_file(&signed, &Output::InPlace, &second, &options).unwrap();
    assert_eq!(outcome.output, signed);

    let report = verify::verify_file(&signed, &offline()).unwrap();
    assert_eq!(status(&report, CheckId::SignatureValid), Status::Pass);
    assert_eq!(
        report.signer.as_ref().unwrap().sha1,
        second.sha1_fingerprint()
    );
    assert_ne!(first.sha1_fingerprint(), second.sha1_fingerprint());
}

/// Offset where the XAR heap starts: header plus compressed TOC.
fn heap_start(data: &[u8]) -> usize {
    let header = u16::from_be_bytes([data[4], data[5]]) as usize;
    let toc = u64::from_be_bytes(data[8..16].try_into().unwrap()) as usize;
    header + toc
}

#[test]
fn tampering_breaks_the_signature() {
    let dir = tempfile::tempdir().unwrap();
    let identity = identity(CertKind::DeveloperIdInstaller);
    let signed = signed_fixture(dir.path(), &identity);
    let original = std::fs::read(&signed).unwrap();

    // A byte of file data (the end of the heap).
    let mut data = original.clone();
    *data.last_mut().unwrap() ^= 0xff;
    std::fs::write(&signed, &data).unwrap();
    let report = verify::verify_file(&signed, &offline()).unwrap();
    let check = report.check(CheckId::SignatureValid).unwrap();
    assert_eq!(check.status, Status::Fail, "{check:#?}");
    assert!(
        check.detail.as_deref().unwrap().contains("modified"),
        "{check:#?}"
    );
    assert!(check.fix.as_deref().unwrap().contains("--resign"));
    assert!(!report.mdm_ready);

    // The table of contents checksum (the start of the heap).
    let mut data = original.clone();
    let checksum_at = heap_start(&data);
    data[checksum_at] ^= 0xff;
    std::fs::write(&signed, &data).unwrap();
    let report = verify::verify_file(&signed, &offline()).unwrap();
    assert_eq!(status(&report, CheckId::SignatureValid), Status::Fail);

    // The RSA signature, which follows the 20-byte SHA-1 checksum.
    let mut data = original;
    let rsa_at = heap_start(&data) + 20 + 8;
    data[rsa_at] ^= 0xff;
    std::fs::write(&signed, &data).unwrap();
    let report = verify::verify_file(&signed, &offline()).unwrap();
    let check = report.check(CheckId::SignatureValid).unwrap();
    assert_eq!(check.status, Status::Fail, "{check:#?}");
    assert!(
        check.detail.as_deref().unwrap().contains("RSA"),
        "{check:#?}"
    );
}

#[test]
fn unsigned_package_is_not_ready() {
    let dir = tempfile::tempdir().unwrap();
    let input = testutil::copy_fixture("unsigned.pkg", dir.path());

    let report = verify::verify_file(&input, &offline()).unwrap();
    assert_eq!(status(&report, CheckId::Format), Status::Pass);
    let signed = report.check(CheckId::Signed).unwrap();
    assert_eq!(signed.status, Status::Fail);
    assert!(signed.fix.as_deref().unwrap().contains("mdmsign sign"));
    for id in [
        CheckId::SignatureValid,
        CheckId::CertificateType,
        CheckId::CertificateChain,
        CheckId::Timestamp,
        CheckId::Notarization,
        CheckId::Staple,
    ] {
        assert_eq!(status(&report, id), Status::Skip, "{id:?}");
    }
    assert!(report.signer.is_none());
    assert!(!report.mdm_ready);
}

#[test]
fn malformed_package_fails_format() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("broken.pkg");
    std::fs::write(&path, b"xar!\0\x1c\0\x01this is not a real archive").unwrap();

    let report = verify::verify_file(&path, &offline()).unwrap();
    let format = report.check(CheckId::Format).unwrap();
    assert_eq!(format.status, Status::Fail);
    assert!(format.fix.is_some());
    assert!(format.detail.is_some());
    assert_eq!(status(&report, CheckId::Signed), Status::Skip);
    assert!(!report.mdm_ready);

    let identity = identity(CertKind::DeveloperIdInstaller);
    let err = sign::sign_file(&path, &Output::Default, &identity, &no_timestamp()).unwrap_err();
    assert!(
        matches!(err, Error::Pkg(PkgError::Malformed { .. })),
        "{err:?}"
    );
}

#[test]
fn timestamp_failure_is_explained() {
    let dir = tempfile::tempdir().unwrap();
    let input = testutil::copy_fixture("unsigned.pkg", dir.path());
    let identity = identity(CertKind::DeveloperIdInstaller);
    // Nothing listens on the discard port, so the connection is refused
    // immediately without touching the network.
    let options = SignOptions {
        timestamp: true,
        timestamp_url: "http://127.0.0.1:9/ts".into(),
        ..SignOptions::default()
    };

    let err = sign::sign_file(&input, &Output::Default, &identity, &options).unwrap_err();
    assert!(
        matches!(err, Error::Pkg(PkgError::Timestamp { .. })),
        "{err:?}"
    );
    assert!(err.to_string().contains("127.0.0.1"), "{err}");
    let hint = err.hint().unwrap();
    assert!(hint.contains("internet connection"), "{hint}");
    assert!(hint.contains("--no-timestamp"), "{hint}");
    assert!(hint.contains("notarization requires a timestamp"), "{hint}");
    assert!(!dir.path().join("unsigned-signed.pkg").exists());
}

#[cfg(target_os = "macos")]
mod macos {
    use std::process::Command;

    use super::*;

    #[test]
    fn pkgutil_reads_native_signature() {
        let dir = tempfile::tempdir().unwrap();
        let identity = identity(CertKind::DeveloperIdInstaller);
        let signed = signed_fixture(dir.path(), &identity);

        let output = Command::new("/usr/sbin/pkgutil")
            .arg("--check-signature")
            .arg(&signed)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(
            text.contains("signed by untrusted certificate"),
            "pkgutil said:\n{text}"
        );
        assert!(
            text.contains(&identity.common_name()),
            "pkgutil said:\n{text}"
        );

        let output = Command::new("/usr/sbin/installer")
            .args(["-pkginfo", "-pkg"])
            .arg(&signed)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "installer -pkginfo failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn system_checks_report_gatekeeper() {
        let dir = tempfile::tempdir().unwrap();
        let identity = identity(CertKind::DeveloperIdInstaller);
        let signed = signed_fixture(dir.path(), &identity);

        let options = VerifyOptions {
            system_checks: true,
            ..offline()
        };
        let report = verify::verify_file(&signed, &options).unwrap();
        let gatekeeper = report.check(CheckId::Gatekeeper).unwrap();
        assert_eq!(gatekeeper.status, Status::Fail, "{gatekeeper:#?}");
        assert!(
            gatekeeper.detail.as_deref().unwrap().contains("pkgutil:"),
            "{gatekeeper:#?}"
        );
    }

    /// Signs with a real Keychain identity through productsign. macOS may
    /// ask for permission to use the key.
    #[test]
    #[ignore = "needs MDMSIGN_TEST_KEYCHAIN_IDENTITY and may show a Keychain prompt"]
    fn productsign_with_keychain_identity() {
        let query = std::env::var("MDMSIGN_TEST_KEYCHAIN_IDENTITY")
            .expect("set MDMSIGN_TEST_KEYCHAIN_IDENTITY to a Developer ID Installer identity");
        let identity = mdmsign_core::keychain::load_identity(&query).unwrap();
        let timestamp = std::env::var("MDMSIGN_TEST_NETWORK").is_ok_and(|v| v == "1");
        let options = SignOptions {
            timestamp,
            ..SignOptions::default()
        };

        let dir = tempfile::tempdir().unwrap();
        let input = testutil::copy_fixture("unsigned.pkg", dir.path());
        let outcome = sign::sign_file(&input, &Output::Default, &identity, &options).unwrap();
        assert_eq!(outcome.backend, "productsign");

        let report = verify::verify_file(&outcome.output, &offline()).unwrap();
        assert_eq!(status(&report, CheckId::SignatureValid), Status::Pass);
        assert_eq!(status(&report, CheckId::CertificateType), Status::Pass);
        assert_eq!(status(&report, CheckId::CertificateChain), Status::Pass);
        assert_eq!(
            report.signer.as_ref().unwrap().sha1,
            identity.sha1_fingerprint()
        );

        // Re-signing an already signed package replaces the signature.
        let resign = SignOptions {
            resign: true,
            ..options
        };
        sign::sign_file(&outcome.output, &Output::InPlace, &identity, &resign).unwrap();
        let report = verify::verify_file(&outcome.output, &offline()).unwrap();
        assert_eq!(status(&report, CheckId::SignatureValid), Status::Pass);
    }
}

/// Verifies a package signed by Apple's own tools with a real certificate.
#[test]
#[ignore = "needs MDMSIGN_TEST_SIGNED_PKG"]
fn real_signed_package_verifies() {
    let path = std::env::var("MDMSIGN_TEST_SIGNED_PKG")
        .expect("set MDMSIGN_TEST_SIGNED_PKG to a package signed with Developer ID Installer");
    let dir = tempfile::tempdir().unwrap();
    let copy = dir.path().join("vendor.pkg");
    std::fs::copy(&path, &copy).unwrap();

    let report = verify::verify_file(&copy, &offline()).unwrap();
    assert_eq!(
        status(&report, CheckId::SignatureValid),
        Status::Pass,
        "{report:#?}"
    );
    assert_eq!(status(&report, CheckId::CertificateType), Status::Pass);
    assert_eq!(status(&report, CheckId::CertificateChain), Status::Pass);
    assert_eq!(status(&report, CheckId::Timestamp), Status::Pass);
}

/// Signs with a real Developer ID Installer `.p12`, with a timestamp.
#[test]
#[ignore = "needs MDMSIGN_TEST_P12_PATH, MDMSIGN_TEST_P12_PASSWORD and the network"]
fn real_p12_signs_with_timestamp() {
    let path = std::env::var("MDMSIGN_TEST_P12_PATH").expect("set MDMSIGN_TEST_P12_PATH");
    let password =
        std::env::var("MDMSIGN_TEST_P12_PASSWORD").expect("set MDMSIGN_TEST_P12_PASSWORD");
    let identity =
        SigningIdentity::from_p12(&std::fs::read(&path).unwrap(), &Secret::new(password), path)
            .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let input = testutil::copy_fixture("unsigned.pkg", dir.path());
    let outcome =
        sign::sign_file(&input, &Output::Default, &identity, &SignOptions::default()).unwrap();
    assert!(outcome.timestamped);

    let report = verify::verify_file(&outcome.output, &offline()).unwrap();
    for id in [
        CheckId::SignatureValid,
        CheckId::CertificateType,
        CheckId::CertificateValidity,
        CheckId::CertificateChain,
        CheckId::Timestamp,
    ] {
        assert_eq!(status(&report, id), Status::Pass, "{id:?}: {report:#?}");
    }
}

/// Gets a real secure timestamp from Apple's server for a test signature.
#[test]
#[ignore = "needs MDMSIGN_TEST_NETWORK=1"]
fn native_signature_gets_apple_timestamp() {
    assert_eq!(
        std::env::var("MDMSIGN_TEST_NETWORK").as_deref(),
        Ok("1"),
        "set MDMSIGN_TEST_NETWORK=1"
    );
    let dir = tempfile::tempdir().unwrap();
    let input = testutil::copy_fixture("unsigned.pkg", dir.path());
    let identity = identity(CertKind::DeveloperIdInstaller);
    let outcome =
        sign::sign_file(&input, &Output::Default, &identity, &SignOptions::default()).unwrap();
    assert!(outcome.timestamped);

    let report = verify::verify_file(&outcome.output, &offline()).unwrap();
    assert_eq!(status(&report, CheckId::SignatureValid), Status::Pass);
    let timestamp = report.check(CheckId::Timestamp).unwrap();
    assert_eq!(timestamp.status, Status::Pass, "{timestamp:#?}");
    assert!(timestamp.summary.contains("UTC"), "{timestamp:#?}");
}

/// Looks up the notarization ticket of a freshly signed package online.
#[test]
#[ignore = "needs MDMSIGN_TEST_NETWORK=1"]
fn online_lookup_reports_not_notarized() {
    assert_eq!(
        std::env::var("MDMSIGN_TEST_NETWORK").as_deref(),
        Ok("1"),
        "set MDMSIGN_TEST_NETWORK=1"
    );
    let dir = tempfile::tempdir().unwrap();
    let identity = identity(CertKind::DeveloperIdInstaller);
    let signed = signed_fixture(dir.path(), &identity);

    let options = VerifyOptions {
        offline: false,
        system_checks: false,
        ..VerifyOptions::default()
    };
    let report = verify::verify_file(&signed, &options).unwrap();
    let check = report.check(CheckId::Notarization).unwrap();
    assert_eq!(check.status, Status::Warn, "{check:#?}");
    assert!(check.fix.as_deref().unwrap().contains("mdmsign notarize"));
}
