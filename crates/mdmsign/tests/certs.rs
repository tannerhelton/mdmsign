//! End-to-end tests of `mdmsign certs` with generated `.p12` files. The
//! real Keychain is never read (`--no-keychain`).

use assert_cmd::Command;
use mdmsign_core::{CertKind, testutil::TestIdentity};
use predicates::prelude::*;

fn mdmsign() -> Command {
    let mut cmd = Command::cargo_bin("mdmsign").unwrap();
    // Isolate from the developer's own credentials and config.
    for var in [
        "MDMSIGN_IDENTITY",
        "MDMSIGN_P12_PATH",
        "MDMSIGN_P12_BASE64",
        "MDMSIGN_P12_PASSWORD",
        "MDMSIGN_ASC_KEY_PATH",
        "MDMSIGN_ASC_KEY",
        "MDMSIGN_ASC_KEY_ID",
        "MDMSIGN_ASC_ISSUER_ID",
        "MDMSIGN_CONFIG",
        "XDG_CONFIG_HOME",
    ] {
        cmd.env_remove(var);
    }
    cmd.env(
        "HOME",
        std::env::temp_dir().join("mdmsign-test-home-does-not-exist"),
    );
    cmd
}

#[test]
fn application_cert_explains_installer_need() {
    let dir = tempfile::tempdir().unwrap();
    let identity = TestIdentity::generate(CertKind::DeveloperIdApplication);
    let p12 = identity.write_p12(dir.path());
    mdmsign()
        .args(["certs", "--no-keychain", "--p12"])
        .arg(&p12)
        .env("MDMSIGN_P12_PASSWORD", &identity.password)
        .assert()
        // It can still sign profiles, so this machine is usable.
        .success()
        .stdout(predicate::str::contains(&identity.common_name))
        .stdout(predicate::str::contains(
            "can't sign .pkg; you need Developer ID Installer",
        ))
        .stdout(predicate::str::contains("Can sign:  .mobileconfig\n"))
        .stdout(predicate::str::contains(
            "✘  no usable Developer ID Installer identity",
        ))
        .stdout(predicate::str::contains("Account Holder"));
}

#[test]
fn installer_cert_json() {
    let dir = tempfile::tempdir().unwrap();
    let identity = TestIdentity::generate(CertKind::DeveloperIdInstaller);
    let p12 = identity.write_p12(dir.path());
    let output = mdmsign()
        .args(["certs", "--json", "--no-keychain", "--p12"])
        .arg(&p12)
        .env("MDMSIGN_P12_PASSWORD", &identity.password)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let json: serde_json::Value = serde_json::from_slice(&output).unwrap();
    let entries = json.as_array().expect("an array of entries");
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry["name"], identity.common_name.as_str());
    assert_eq!(entry["kind"], "developer-id-installer");
    assert_eq!(entry["source"], p12.display().to_string());
    assert_eq!(entry["usable"], true);
    assert_eq!(
        entry["can_sign"],
        serde_json::json!(["flat-package", "configuration-profile"])
    );
    assert!(entry["notes"].is_array());
}

#[test]
fn nothing_usable_exits_1_with_advice() {
    mdmsign()
        .args(["certs", "--no-keychain"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("No signing identities to show."))
        .stdout(predicate::str::contains("Developer ID Installer"));
}

#[test]
fn wrong_password_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    let identity = TestIdentity::generate(CertKind::DeveloperIdInstaller);
    let p12 = identity.write_p12(dir.path());
    mdmsign()
        .args(["certs", "--no-keychain", "--p12"])
        .arg(&p12)
        .env("MDMSIGN_P12_PASSWORD", "nope")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("password"));
}
