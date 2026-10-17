//! End-to-end tests of `mdmsign notarize` and `mdmsign staple` that fail
//! before contacting Apple.

use assert_cmd::Command;
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

/// A syntactically plausible but unusable API key, so nothing reaches Apple.
fn with_fake_asc(cmd: &mut Command) -> &mut Command {
    cmd.env(
        "MDMSIGN_ASC_KEY",
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
    )
    .env("MDMSIGN_ASC_KEY_ID", "ABC123DEFG")
    .env(
        "MDMSIGN_ASC_ISSUER_ID",
        "00000000-0000-0000-0000-000000000000",
    )
}

#[test]
fn notarize_without_credentials_explains_api_key() {
    let dir = tempfile::tempdir().unwrap();
    let pkg = mdmsign_core::testutil::copy_fixture("unsigned.pkg", dir.path());
    mdmsign()
        .arg("notarize")
        .arg(&pkg)
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "error: missing App Store Connect API key",
        ))
        .stderr(predicate::str::contains("--key"))
        .stderr(predicate::str::contains("Issuer ID"));
}

#[test]
fn notarize_without_issuer_names_the_flag() {
    let dir = tempfile::tempdir().unwrap();
    let pkg = mdmsign_core::testutil::copy_fixture("unsigned.pkg", dir.path());
    let key = dir.path().join("AuthKey_ABC123DEFG.p8");
    std::fs::write(
        &key,
        "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
    )
    .unwrap();
    mdmsign()
        .arg("notarize")
        .arg(&pkg)
        .arg("--key")
        .arg(&key)
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "error: missing App Store Connect issuer ID",
        ))
        .stderr(predicate::str::contains("--issuer"))
        .stderr(predicate::str::contains("MDMSIGN_ASC_ISSUER_ID"));
}

#[test]
fn notarize_profile_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let profile = mdmsign_core::testutil::write_sample_profile(dir.path());
    with_fake_asc(mdmsign().arg("notarize").arg(&profile))
        .assert()
        .code(1)
        .stderr(predicate::str::contains("profiles don't need it"))
        .stderr(predicate::str::contains("fix:"));
}

#[test]
fn notarize_never_prints_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let pkg = mdmsign_core::testutil::copy_fixture("unsigned.pkg", dir.path());
    with_fake_asc(mdmsign().arg("notarize").arg(&pkg))
        .assert()
        .code(1)
        .stderr(predicate::str::contains("AAAA").not());
}

#[test]
fn staple_profile_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let profile = mdmsign_core::testutil::write_sample_profile(dir.path());
    mdmsign()
        .arg("staple")
        .arg(&profile)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("can't staple"));
}

#[test]
fn staple_missing_file() {
    mdmsign()
        .args(["staple", "/definitely/not/here.pkg"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("file not found"));
}
