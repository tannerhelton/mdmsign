//! End-to-end tests of `mdmsign sign` and `mdmsign verify` on `.pkg` files,
//! using throwaway self-signed certificates.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use mdmsign_core::{CertKind, testutil};
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

/// Writes a test identity of `kind` and returns the `.p12` path and password.
fn p12(dir: &Path, kind: CertKind) -> (PathBuf, String) {
    let identity = testutil::TestIdentity::generate(kind);
    (identity.write_p12(dir), identity.password.clone())
}

/// Signs a copy of the fixture with the CLI and returns the signed path.
fn sign_fixture(dir: &Path) -> PathBuf {
    let input = testutil::copy_fixture("unsigned.pkg", dir);
    let (p12, password) = p12(dir, CertKind::DeveloperIdInstaller);
    mdmsign()
        .arg("sign")
        .arg(&input)
        .arg("--p12")
        .arg(&p12)
        .arg("--no-timestamp")
        .env("MDMSIGN_P12_PASSWORD", &password)
        .assert()
        .success();
    dir.join("unsigned-signed.pkg")
}

#[test]
fn sign_writes_signed_copy() {
    let dir = tempfile::tempdir().unwrap();
    let input = testutil::copy_fixture("unsigned.pkg", dir.path());
    let (p12, password) = p12(dir.path(), CertKind::DeveloperIdInstaller);
    let before = std::fs::read(&input).unwrap();

    mdmsign()
        .arg("sign")
        .arg(&input)
        .arg("--p12")
        .arg(&p12)
        .arg("--no-timestamp")
        .env("MDMSIGN_P12_PASSWORD", &password)
        .assert()
        .success()
        .stdout(predicate::str::contains("unsigned-signed.pkg"))
        .stdout(predicate::str::contains("apple-codesign"))
        .stderr(predicate::str::contains("mdmsign notarize"))
        .stderr(predicate::str::contains(&password).not());

    assert!(dir.path().join("unsigned-signed.pkg").is_file());
    assert_eq!(std::fs::read(&input).unwrap(), before, "input changed");
}

#[test]
fn sign_refuses_application_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let input = testutil::copy_fixture("unsigned.pkg", dir.path());
    let (p12, password) = p12(dir.path(), CertKind::DeveloperIdApplication);

    mdmsign()
        .arg("sign")
        .arg(&input)
        .arg("--p12")
        .arg(&p12)
        .arg("--no-timestamp")
        .env("MDMSIGN_P12_PASSWORD", &password)
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "you need a Developer ID Installer certificate",
        ))
        .stderr(predicate::str::contains("fix:"));
    assert!(!dir.path().join("unsigned-signed.pkg").exists());
}

#[test]
fn sign_twice_suggests_resign() {
    let dir = tempfile::tempdir().unwrap();
    let signed = sign_fixture(dir.path());
    let (p12, password) = p12(dir.path(), CertKind::DeveloperIdInstaller);

    mdmsign()
        .arg("sign")
        .arg(&signed)
        .arg("--in-place")
        .arg("--p12")
        .arg(&p12)
        .arg("--no-timestamp")
        .env("MDMSIGN_P12_PASSWORD", &password)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("already signed"))
        .stderr(predicate::str::contains("--resign"));

    mdmsign()
        .arg("sign")
        .arg(&signed)
        .arg("--in-place")
        .arg("--resign")
        .arg("--p12")
        .arg(&p12)
        .arg("--no-timestamp")
        .env("MDMSIGN_P12_PASSWORD", &password)
        .assert()
        .success();
}

#[test]
fn verify_json_reports_self_signed_chain() {
    let dir = tempfile::tempdir().unwrap();
    let signed = sign_fixture(dir.path());

    let output = mdmsign()
        .args(["verify", "--offline", "--no-system-checks", "--json"])
        .arg(&signed)
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(report["kind"], "flat-package");
    assert_eq!(report["mdm_ready"], false);
    assert_eq!(report["signer"]["cert_kind"], "developer-id-installer");

    let status = |id: &str| {
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap_or_else(|| panic!("no {id} check in {report:#}"))["status"]
            .clone()
    };
    assert_eq!(status("signature-valid"), "pass");
    assert_eq!(status("certificate-type"), "pass");
    assert_eq!(status("certificate-chain"), "fail");
    assert_eq!(status("timestamp"), "warn");
    assert_eq!(status("notarization"), "skip");
}

#[test]
fn verify_human_output_has_fixes() {
    let dir = tempfile::tempdir().unwrap();
    let signed = sign_fixture(dir.path());

    mdmsign()
        .args(["verify", "--offline"])
        .arg(&signed)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("PASS  Signature is valid"))
        .stdout(predicate::str::contains(
            "FAIL  Certificate isn't issued by Apple",
        ))
        .stdout(predicate::str::contains("WARN  No secure timestamp"))
        .stdout(predicate::str::contains("fix: "))
        .stdout(predicate::str::contains("Result: FAIL: not MDM-ready"));
}

#[test]
fn verify_unsigned_package() {
    let dir = tempfile::tempdir().unwrap();
    let input = testutil::copy_fixture("unsigned.pkg", dir.path());

    mdmsign()
        .args(["verify", "--offline", "--no-system-checks"])
        .arg(&input)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("FAIL  Not signed"))
        .stdout(predicate::str::contains("fix: Sign it"))
        .stdout(predicate::str::contains("mdmsign sign"));
}
