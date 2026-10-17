//! End-to-end tests of `mdmsign sign` and `mdmsign verify` on profiles.

use std::path::{Path, PathBuf};

use assert_cmd::Command;
use mdmsign_core::{
    CertKind,
    testutil::{self, TestIdentity},
};
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

/// A sample profile and a `.p12` to sign it with.
struct Fixture {
    dir: tempfile::TempDir,
    profile: PathBuf,
    p12: PathBuf,
    password: String,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let profile = testutil::write_sample_profile(dir.path());
        let identity = TestIdentity::generate(CertKind::DeveloperIdApplication);
        let p12 = identity.write_p12(dir.path());
        Self {
            dir,
            profile,
            p12,
            password: identity.password,
        }
    }

    fn sign(&self, file: &Path) -> Command {
        let mut cmd = mdmsign();
        cmd.arg("sign")
            .arg(file)
            .arg("--p12")
            .arg(&self.p12)
            .env("MDMSIGN_P12_PASSWORD", &self.password);
        cmd
    }

    fn signed_path(&self) -> PathBuf {
        self.dir.path().join("sample-signed.mobileconfig")
    }
}

fn verify_json(file: &Path) -> serde_json::Value {
    let output = mdmsign()
        .args(["verify", "--json", "--no-system-checks"])
        .arg(file)
        .output()
        .unwrap();
    serde_json::from_slice(&output.stdout).unwrap_or_else(|e| {
        panic!(
            "invalid JSON ({e}): {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[test]
fn sign_writes_signed_copy() {
    let fx = Fixture::new();
    fx.sign(&fx.profile)
        .assert()
        .success()
        .stdout(predicate::str::contains("sample-signed.mobileconfig"))
        .stderr(predicate::str::contains(&fx.password).not());
    let signed = fx.signed_path();
    assert!(signed.exists());
    // The input is untouched.
    assert_eq!(
        std::fs::read_to_string(&fx.profile).unwrap(),
        testutil::SAMPLE_PROFILE
    );
    assert_eq!(std::fs::read(&signed).unwrap()[0], 0x30);
}

#[test]
fn second_sign_refuses_to_overwrite() {
    let fx = Fixture::new();
    fx.sign(&fx.profile).assert().success();
    fx.sign(&fx.profile)
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"))
        .stderr(predicate::str::contains("fix:"))
        .stderr(predicate::str::contains("--force"));
}

#[test]
fn sign_already_signed_needs_resign() {
    let fx = Fixture::new();
    fx.sign(&fx.profile).assert().success();
    let signed = fx.signed_path();
    fx.sign(&signed)
        .arg("--in-place")
        .assert()
        .failure()
        .stderr(predicate::str::contains("already signed"))
        .stderr(predicate::str::contains("--resign"));
    fx.sign(&signed)
        .args(["--in-place", "--resign"])
        .assert()
        .success();
    assert_eq!(verify_json(&signed)["mdm_ready"], true);
}

#[test]
fn sign_in_place() {
    let fx = Fixture::new();
    fx.sign(&fx.profile).arg("--in-place").assert().success();
    assert!(!fx.signed_path().exists());
    assert_eq!(std::fs::read(&fx.profile).unwrap()[0], 0x30);
    let json = verify_json(&fx.profile);
    assert_eq!(json["mdm_ready"], true);
}

#[test]
fn sign_rejects_non_profile() {
    let fx = Fixture::new();
    let payload = fx.dir.path().join("payload.mobileconfig");
    std::fs::write(
        &payload,
        r#"<?xml version="1.0"?><plist version="1.0"><dict><key>PayloadType</key><string>com.apple.wifi.managed</string></dict></plist>"#,
    )
    .unwrap();
    fx.sign(&payload)
        .assert()
        .failure()
        .stderr(predicate::str::contains("isn't a configuration profile"))
        .stderr(predicate::str::contains("fix:"))
        .stderr(predicate::str::contains("PayloadContent"));
    assert!(!fx.dir.path().join("payload-signed.mobileconfig").exists());
}

#[test]
fn verify_json_for_signed_profile() {
    let fx = Fixture::new();
    fx.sign(&fx.profile).assert().success();
    let json = verify_json(&fx.signed_path());
    assert_eq!(json["kind"], "configuration-profile");
    assert_eq!(json["mdm_ready"], true);
    assert_eq!(json["signer"]["cert_kind"], "developer-id-application");
    let status = |id: &str| {
        json["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["id"] == id)
            .unwrap_or_else(|| panic!("no {id} check in {json}"))["status"]
            .clone()
    };
    assert_eq!(status("signature-valid"), "pass");
    assert_eq!(status("profile-content"), "pass");
    assert_eq!(status("certificate-chain"), "warn");
}

#[test]
fn verify_unsigned_profile_passes_with_warning() {
    let fx = Fixture::new();
    mdmsign()
        .args(["verify", "--no-system-checks"])
        .arg(&fx.profile)
        .assert()
        .success()
        .stdout(predicate::str::contains("WARN  Not signed"))
        .stdout(predicate::str::contains("mdmsign sign"))
        .stdout(predicate::str::contains("Result: PASS"));
}

#[test]
fn verify_tampered_profile_fails() {
    let fx = Fixture::new();
    fx.sign(&fx.profile).assert().success();
    let signed = fx.signed_path();
    let mut data = std::fs::read(&signed).unwrap();
    let needle = b"com.example.mdmsign.test";
    let at = data
        .windows(needle.len())
        .position(|w| w == needle)
        .unwrap();
    data[at] = b'C';
    std::fs::write(&signed, data).unwrap();
    mdmsign()
        .args(["verify", "--no-system-checks"])
        .arg(&signed)
        .assert()
        .code(1)
        .stdout(predicate::str::contains("FAIL"))
        .stdout(predicate::str::contains("--resign"))
        .stdout(predicate::str::contains("Result: FAIL"));
}
