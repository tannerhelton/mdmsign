//! Notarization and stapling. Everything here runs offline except the
//! `#[ignore]`d test at the bottom, which talks to Apple and needs real
//! credentials.
#![cfg(feature = "test-util")]

use std::{path::PathBuf, time::Duration};

use mdmsign_core::{
    ArtifactKind, Error, Secret,
    credentials::AscCredentials,
    notarize::{self, NotarizeError, NotarizeOptions, NotarizeOutcome, NotaryLog, StapleOutcome},
    testutil,
};

/// Credentials that fail before any request is made.
fn unusable_credentials() -> AscCredentials {
    AscCredentials {
        key_id: "ABC123DEFG".into(),
        issuer_id: "00000000-0000-0000-0000-000000000000".into(),
        private_key_pem: Secret::new(
            "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
        ),
        source: "AuthKey_ABC123DEFG.p8".into(),
    }
}

fn notarize_err(path: &std::path::Path) -> Error {
    notarize::notarize(
        path,
        &unusable_credentials(),
        &NotarizeOptions::default(),
        &mut |_| {},
    )
    .unwrap_err()
}

#[test]
fn profiles_are_not_notarized() {
    let dir = tempfile::tempdir().unwrap();
    let profile = testutil::write_sample_profile(dir.path());
    let err = notarize_err(&profile);
    assert!(
        matches!(
            err,
            Error::Notarize(NotarizeError::NotAPackage {
                kind: ArtifactKind::ConfigurationProfile,
                ..
            })
        ),
        "{err:?}"
    );
    assert!(
        err.to_string()
            .contains("notarization in mdmsign is for .pkg installers, and profiles don't need it"),
        "{err}"
    );
    assert!(err.hint().unwrap().contains("mdmsign sign"));

    let err = notarize::staple(&profile).unwrap_err();
    assert!(err.to_string().starts_with("can't staple"), "{err}");
}

#[test]
fn bad_api_key_is_a_usage_error_before_upload() {
    let dir = tempfile::tempdir().unwrap();
    let pkg = testutil::copy_fixture("unsigned.pkg", dir.path());
    let err = notarize_err(&pkg);
    assert!(
        matches!(err, Error::Notarize(NotarizeError::InvalidApiKey { .. })),
        "{err:?}"
    );
    assert!(err.is_usage_error());
    assert!(err.hint().unwrap().contains(".p8"));
    // The key never shows up in messages.
    assert!(!format!("{err:?}").contains("AAAA"));
}

#[test]
fn missing_file() {
    let err = notarize_err(std::path::Path::new("/definitely/not/here.pkg"));
    assert!(matches!(err, Error::FileNotFound(_)), "{err:?}");
}

#[test]
fn parses_notarization_log() {
    let log = NotaryLog::parse(&serde_json::json!({
        "logFormatVersion": 1,
        "jobId": "2efe2717-52ef-43a5-96dc-0797e4ca1041",
        "status": "Invalid",
        "statusSummary": "Archive contains critical validation errors",
        "statusCode": 4000,
        "issues": [{
            "severity": "error",
            "code": null,
            "path": "Example.pkg",
            "message": "The signature of the binary is invalid.",
            "docUrl": "https://developer.apple.com/documentation/security/resolving-common-notarization-issues",
            "architecture": "x86_64"
        }]
    }));
    assert_eq!(log.issues.len(), 1);
    let issue = &log.issues[0];
    assert_eq!(issue.path.as_deref(), Some("Example.pkg"));
    assert_eq!(
        issue.to_string(),
        "error: The signature of the binary is invalid. (Example.pkg, x86_64) See https://developer.apple.com/documentation/security/resolving-common-notarization-issues"
    );
    let json = serde_json::to_value(issue).unwrap();
    assert_eq!(json["doc_url"], issue.doc_url.as_deref().unwrap());
}

#[test]
fn hints_explain_what_to_do() {
    let path = PathBuf::from("Example.pkg");
    let timeout = NotarizeError::Timeout {
        submission_id: "sub-1".into(),
        path: path.clone(),
        waited: Duration::from_secs(30 * 60),
    };
    assert_eq!(
        timeout.to_string(),
        "Apple is still processing submission sub-1 after 30 minutes"
    );
    assert!(
        timeout
            .hint()
            .unwrap()
            .contains("run `mdmsign staple Example.pkg` later")
    );

    let no_ticket = NotarizeError::NoTicket { path };
    let hint = no_ticket.hint().unwrap();
    assert!(hint.contains("hasn't been notarized"), "{hint}");
    assert!(hint.contains("still processing"), "{hint}");
    assert!(hint.contains("changed after it was notarized"), "{hint}");

    let auth = NotarizeError::Auth {
        detail: "HTTP 401".into(),
    };
    let hint = auth.hint().unwrap();
    assert!(
        hint.contains("issuer ID") && hint.contains("key ID"),
        "{hint}"
    );
    assert!(hint.contains("Developer or higher"), "{hint}");

    let network = NotarizeError::Network {
        action: "upload the package to Apple",
        detail: "dns error".into(),
    };
    assert!(network.hint().unwrap().contains("HTTPS_PROXY"));
    assert!(!network.is_usage_error());
    assert!(auth.is_usage_error());
    assert!(!timeout.is_usage_error());
}

/// Notarizes and staples a real signed package. Needs:
///
/// - `MDMSIGN_TEST_NOTARIZE_PKG`: a `.pkg` signed with Developer ID Installer
///   (it's copied; the original isn't modified),
/// - `MDMSIGN_ASC_KEY_PATH` (or `MDMSIGN_ASC_KEY`), `MDMSIGN_ASC_KEY_ID` and
///   `MDMSIGN_ASC_ISSUER_ID`.
///
/// Run with `cargo test -p mdmsign-core --all-features --test notarize -- --ignored --nocapture`.
#[test]
#[ignore = "uploads to Apple's notary service; needs MDMSIGN_TEST_NOTARIZE_PKG and MDMSIGN_ASC_*"]
fn notarizes_and_staples_real_package() {
    use mdmsign_core::{
        config::Config,
        credentials::{AscArgs, ProcessEnv, load_asc_credentials},
    };

    let source = PathBuf::from(
        std::env::var("MDMSIGN_TEST_NOTARIZE_PKG")
            .expect("set MDMSIGN_TEST_NOTARIZE_PKG to a signed .pkg"),
    );
    let creds = load_asc_credentials(&AscArgs::default(), &ProcessEnv, &Config::default())
        .expect("set MDMSIGN_ASC_KEY_PATH, MDMSIGN_ASC_KEY_ID and MDMSIGN_ASC_ISSUER_ID");
    let dir = tempfile::tempdir().unwrap();
    let pkg = dir.path().join(source.file_name().unwrap());
    std::fs::copy(&source, &pkg).unwrap();

    let outcome = notarize::notarize(&pkg, &creds, &NotarizeOptions::default(), &mut |line| {
        eprintln!("{line}")
    })
    .unwrap_or_else(|e| panic!("{e}\n{}", e.hint().unwrap_or_default()));
    let NotarizeOutcome::Accepted { stapled, .. } = outcome else {
        panic!("{outcome:?}")
    };
    assert!(stapled, "the ticket should have been stapled");
    assert_eq!(
        notarize::staple(&pkg).unwrap(),
        StapleOutcome::AlreadyStapled
    );
}
