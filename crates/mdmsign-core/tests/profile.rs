//! Signing and verifying configuration profiles end to end.

#![cfg(feature = "test-util")]

use std::path::{Path, PathBuf};

use mdmsign_core::{
    CertKind, Error, Secret, SigningIdentity,
    sign::{
        self, Backend, Output, SignOptions,
        profile::{ProfileError, is_signed},
    },
    testutil::{self, TestIdentity},
    verify::{self, CheckId, Status, VerifyOptions},
};

fn identity() -> SigningIdentity {
    let test = TestIdentity::generate(CertKind::DeveloperIdApplication);
    SigningIdentity::from_p12(&test.p12, &Secret::new(&test.password), "test.p12").unwrap()
}

fn options() -> SignOptions {
    SignOptions {
        backend: Backend::Native,
        ..SignOptions::default()
    }
}

/// Verify options without the macOS system check, so results are the same
/// on every platform.
fn offline() -> VerifyOptions {
    VerifyOptions {
        offline: true,
        require_notarization: false,
        system_checks: false,
    }
}

fn sign_sample(dir: &Path, identity: &SigningIdentity) -> PathBuf {
    let input = testutil::write_sample_profile(dir);
    let outcome = sign::sign_file(&input, &Output::Default, identity, &options()).unwrap();
    assert_eq!(outcome.output, dir.join("sample-signed.mobileconfig"));
    assert_eq!(outcome.backend, "cms");
    assert!(!outcome.timestamped, "profiles are never timestamped");
    outcome.output
}

fn status(report: &verify::Report, id: CheckId) -> Status {
    report
        .check(id)
        .unwrap_or_else(|| panic!("missing {id:?} check: {report:#?}"))
        .status
}

#[test]
fn sign_then_verify_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let identity = identity();
    let signed = sign_sample(dir.path(), &identity);

    assert!(is_signed(&signed).unwrap());
    assert!(!is_signed(&dir.path().join("sample.mobileconfig")).unwrap());

    let report = verify::verify_file(&signed, &offline()).unwrap();
    assert!(report.mdm_ready, "{report:#?}");
    assert_eq!(status(&report, CheckId::Format), Status::Pass);
    assert_eq!(status(&report, CheckId::ProfileContent), Status::Pass);
    assert_eq!(status(&report, CheckId::Signed), Status::Pass);
    assert_eq!(status(&report, CheckId::SignatureValid), Status::Pass);
    assert_eq!(status(&report, CheckId::CertificateType), Status::Pass);
    assert_eq!(status(&report, CheckId::CertificateValidity), Status::Pass);
    // Self-signed test certificates don't chain to Apple.
    assert_eq!(status(&report, CheckId::CertificateChain), Status::Warn);

    let signer = report.signer.as_ref().unwrap();
    assert_eq!(signer.common_name, identity.common_name());
    assert_eq!(signer.cert_kind, CertKind::DeveloperIdApplication);
    assert_eq!(signer.sha1, identity.sha1_fingerprint());
}

#[test]
fn signed_content_is_the_original_profile() {
    let dir = tempfile::tempdir().unwrap();
    let signed = sign_sample(dir.path(), &identity());
    let data = std::fs::read(&signed).unwrap();
    let parsed = sign::profile::parse_signed_data(&data).unwrap();
    assert_eq!(
        sign::profile::signed_content(&parsed).unwrap(),
        testutil::SAMPLE_PROFILE.as_bytes()
    );
}

#[test]
fn refuses_already_signed_without_resign() {
    let dir = tempfile::tempdir().unwrap();
    let identity = identity();
    let signed = sign_sample(dir.path(), &identity);
    let err = sign::sign_file(&signed, &Output::InPlace, &identity, &options()).unwrap_err();
    assert!(matches!(err, Error::AlreadySigned { .. }), "{err:?}");
    assert!(err.hint().unwrap().contains("--resign"));
}

#[test]
fn resign_replaces_the_signature() {
    let dir = tempfile::tempdir().unwrap();
    let first = identity();
    let signed = sign_sample(dir.path(), &first);

    let second = identity();
    assert_ne!(first.sha1_fingerprint(), second.sha1_fingerprint());
    let options = SignOptions {
        resign: true,
        ..options()
    };
    let outcome = sign::sign_file(&signed, &Output::InPlace, &second, &options).unwrap();
    assert_eq!(outcome.output, signed);

    let data = std::fs::read(&signed).unwrap();
    let parsed = sign::profile::parse_signed_data(&data).unwrap();
    // The old signature was unwrapped, not nested.
    assert_eq!(
        sign::profile::signed_content(&parsed).unwrap(),
        testutil::SAMPLE_PROFILE.as_bytes()
    );
    assert_eq!(parsed.signers().count(), 1);

    let report = verify::verify_file(&signed, &offline()).unwrap();
    assert!(report.mdm_ready, "{report:#?}");
    assert_eq!(report.signer.unwrap().sha1, second.sha1_fingerprint());
}

#[test]
fn tampered_profile_fails_signature_check() {
    let dir = tempfile::tempdir().unwrap();
    let signed = sign_sample(dir.path(), &identity());
    let mut data = std::fs::read(&signed).unwrap();
    let needle = b"mdmsign test profile";
    let at = data
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("profile content is stored inline");
    data[at] = b'M';
    std::fs::write(&signed, &data).unwrap();

    let report = verify::verify_file(&signed, &offline()).unwrap();
    assert!(!report.mdm_ready);
    let check = report.check(CheckId::SignatureValid).unwrap();
    assert_eq!(check.status, Status::Fail, "{report:#?}");
    assert!(check.fix.as_deref().unwrap().contains("--resign"));
    // The content itself is still a valid profile.
    assert_eq!(status(&report, CheckId::ProfileContent), Status::Pass);
}

#[test]
fn tampering_is_caught_when_signing_over_it() {
    // A corrupt signature must never be silently re-signed without --resign,
    // and with --resign the damaged content is still validated.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("broken.mobileconfig");
    std::fs::write(&path, [0x30, 0x82, 0x00, 0x05, 0x01, 0x02]).unwrap();
    let options = SignOptions {
        resign: true,
        ..options()
    };
    let err = sign::sign_file(&path, &Output::Default, &identity(), &options).unwrap_err();
    assert!(
        matches!(
            err,
            Error::Profile(ProfileError::UnreadableSignature { .. })
        ),
        "{err:?}"
    );
    assert!(err.hint().is_some());

    let report = verify::verify_file(&path, &offline()).unwrap();
    assert_eq!(status(&report, CheckId::Format), Status::Fail);
    assert_eq!(status(&report, CheckId::SignatureValid), Status::Skip);
    assert!(!report.mdm_ready);
}

#[test]
fn non_profile_plist_is_rejected_with_hint() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wifi.mobileconfig");
    std::fs::write(
        &path,
        r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
	<key>PayloadType</key>
	<string>com.apple.wifi.managed</string>
	<key>SSID_STR</key>
	<string>Example</string>
</dict>
</plist>
"#,
    )
    .unwrap();

    let err = sign::sign_file(&path, &Output::Default, &identity(), &options()).unwrap_err();
    assert!(
        matches!(
            err,
            Error::Profile(ProfileError::NotAConfigurationProfile { .. })
        ),
        "{err:?}"
    );
    assert!(err.to_string().contains("com.apple.wifi.managed"), "{err}");
    assert!(err.hint().unwrap().contains("PayloadContent"));
    assert!(!dir.path().join("wifi-signed.mobileconfig").exists());

    let report = verify::verify_file(&path, &offline()).unwrap();
    assert!(!report.mdm_ready);
    let check = report.check(CheckId::ProfileContent).unwrap();
    assert_eq!(check.status, Status::Fail);
    assert!(check.fix.is_some());
}

#[test]
fn invalid_plist_is_rejected_with_plutil_hint() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("broken.mobileconfig");
    std::fs::write(&path, "<?xml version=\"1.0\"?><plist><dict><key>x</dict>").unwrap();

    let err = sign::sign_file(&path, &Output::Default, &identity(), &options()).unwrap_err();
    assert!(err.hint().unwrap().contains("plutil -lint"), "{err:?}");

    let report = verify::verify_file(&path, &offline()).unwrap();
    let check = report.check(CheckId::Format).unwrap();
    assert_eq!(check.status, Status::Fail);
    assert!(check.fix.as_deref().unwrap().contains("plutil -lint"));
}

#[test]
fn unsigned_profile_is_mdm_ready_with_warning() {
    let dir = tempfile::tempdir().unwrap();
    let path = testutil::write_sample_profile(dir.path());
    let report = verify::verify_file(&path, &offline()).unwrap();
    assert!(report.mdm_ready, "{report:#?}");
    let signed = report.check(CheckId::Signed).unwrap();
    assert_eq!(signed.status, Status::Warn);
    assert!(signed.fix.as_deref().unwrap().contains("mdmsign sign"));
    for id in [
        CheckId::SignatureValid,
        CheckId::CertificateType,
        CheckId::CertificateValidity,
        CheckId::CertificateChain,
    ] {
        assert_eq!(status(&report, id), Status::Skip);
    }
    assert!(report.signer.is_none());
}

#[test]
fn json_report_shape() {
    let dir = tempfile::tempdir().unwrap();
    let signed = sign_sample(dir.path(), &identity());
    let report = verify::verify_file(&signed, &offline()).unwrap();
    let json = serde_json::to_value(&report).unwrap();
    assert_eq!(json["kind"], "configuration-profile");
    assert_eq!(json["mdm_ready"], true);
    assert_eq!(json["signer"]["cert_kind"], "developer-id-application");
    assert_eq!(json["signer"]["team_id"], testutil::TEAM_ID);
    let checks = json["checks"].as_array().unwrap();
    let ids: Vec<&str> = checks.iter().map(|c| c["id"].as_str().unwrap()).collect();
    assert_eq!(
        ids,
        [
            "format",
            "profile-content",
            "signed",
            "signature-valid",
            "certificate-type",
            "certificate-validity",
            "certificate-chain",
        ]
    );
    let chain = &checks[6];
    assert_eq!(chain["status"], "warn");
    assert!(chain["fix"].is_string());
}

#[test]
fn binary_profile_signs_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let value = plist::Value::from_reader(std::io::Cursor::new(testutil::SAMPLE_PROFILE)).unwrap();
    let path = dir.path().join("binary.mobileconfig");
    value.to_file_binary(&path).unwrap();
    let outcome = sign::sign_file(&path, &Output::Default, &identity(), &options()).unwrap();
    let report = verify::verify_file(&outcome.output, &offline()).unwrap();
    assert!(report.mdm_ready, "{report:#?}");
    assert!(
        report
            .check(CheckId::Format)
            .unwrap()
            .summary
            .contains("binary")
    );
}

/// Cross-checks native output with OpenSSL's CMS parser and macOS's trust
/// evaluation.
///
/// Deliberately no `security cms -D` here: it imports every certificate
/// embedded in the profile into the default keychain, which tests must not
/// touch. Set `MDMSIGN_TEST_SECURITY_CMS_DECODE=1` and run with `--ignored`
/// to opt in on a throwaway machine.
#[cfg(target_os = "macos")]
mod macos {
    use std::process::Command;

    use super::*;

    #[test]
    #[ignore = "`security cms -D` imports the test certificate into the default keychain"]
    fn security_cms_decodes_native_output() {
        if std::env::var_os("MDMSIGN_TEST_SECURITY_CMS_DECODE").is_none() {
            eprintln!("MDMSIGN_TEST_SECURITY_CMS_DECODE not set; skipping");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let signed = sign_sample(dir.path(), &identity());
        let out = Command::new("/usr/bin/security")
            .args(["cms", "-D", "-i"])
            .arg(&signed)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(out.stdout, testutil::SAMPLE_PROFILE.as_bytes());
    }

    #[test]
    fn system_check_warns_on_untrusted_test_certificate() {
        let dir = tempfile::tempdir().unwrap();
        let signed = sign_sample(dir.path(), &identity());
        let report = verify::verify_file(
            &signed,
            &VerifyOptions {
                system_checks: true,
                ..offline()
            },
        )
        .unwrap();
        let check = report.check(CheckId::Gatekeeper).unwrap();
        assert_eq!(check.status, Status::Warn, "{check:#?}");
        assert!(report.mdm_ready);
    }

    #[test]
    fn openssl_verifies_native_output() {
        let Ok(version) = Command::new("openssl").arg("version").output() else {
            eprintln!("openssl not installed; skipping");
            return;
        };
        if !version.status.success() {
            eprintln!("openssl not usable; skipping");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let signed = sign_sample(dir.path(), &identity());
        let content = dir.path().join("content.plist");
        let out = Command::new("openssl")
            .args(["cms", "-verify", "-noverify", "-inform", "DER", "-in"])
            .arg(&signed)
            .arg("-out")
            .arg(&content)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            std::fs::read(&content).unwrap(),
            testutil::SAMPLE_PROFILE.as_bytes()
        );
    }

    /// Signs with a real Keychain identity via `security cms`.
    ///
    /// Set `MDMSIGN_TEST_KEYCHAIN_IDENTITY` to the SHA-1 or name of an
    /// identity in your Keychain and run with `--ignored`. macOS may ask for
    /// permission to use the key.
    #[test]
    #[ignore = "needs a Keychain identity in MDMSIGN_TEST_KEYCHAIN_IDENTITY"]
    fn keychain_identity_round_trip() {
        let query = std::env::var("MDMSIGN_TEST_KEYCHAIN_IDENTITY")
            .expect("set MDMSIGN_TEST_KEYCHAIN_IDENTITY");
        let identity = mdmsign_core::keychain::load_identity(&query).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let input = testutil::write_sample_profile(dir.path());
        let outcome =
            sign::sign_file(&input, &Output::Default, &identity, &SignOptions::default()).unwrap();
        assert_eq!(outcome.backend, "security cms");
        let report = verify::verify_file(&outcome.output, &offline()).unwrap();
        assert!(report.mdm_ready, "{report:#?}");
        assert_eq!(report.signer.unwrap().sha1, identity.sha1_fingerprint());

        // Re-signing unwraps the old signature.
        let resign = SignOptions {
            resign: true,
            ..SignOptions::default()
        };
        sign::sign_file(&outcome.output, &Output::InPlace, &identity, &resign).unwrap();
        let data = std::fs::read(&outcome.output).unwrap();
        let parsed = sign::profile::parse_signed_data(&data).unwrap();
        assert_eq!(
            sign::profile::signed_content(&parsed).unwrap(),
            testutil::SAMPLE_PROFILE.as_bytes()
        );
    }
}
