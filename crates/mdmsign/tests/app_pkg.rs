//! `mdmsign pkg`: wrapping an installed app in a signed package.

use assert_cmd::Command;
use mdmsign_core::testutil;
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
fn sign_on_an_app_points_to_pkg() {
    let dir = tempfile::tempdir().unwrap();
    let app = testutil::make_test_app(dir.path(), "Demo", "com.example.demo", "1.0");
    mdmsign()
        .arg("sign")
        .arg(&app)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("mdmsign pkg"));
}

#[test]
fn pkg_rejects_non_apps_before_asking_for_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("notes.txt");
    std::fs::write(&file, "hi").unwrap();
    mdmsign()
        .arg("pkg")
        .arg(&file)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("isn't an app bundle"))
        .stderr(predicate::str::contains("signing identity").not());
}

#[cfg(target_os = "macos")]
#[test]
fn pkg_builds_signed_package_with_default_name() {
    let dir = tempfile::tempdir().unwrap();
    let app = testutil::make_test_app(dir.path(), "Demo", "com.example.demo", "1.0");
    let identity = testutil::TestIdentity::generate(mdmsign_core::CertKind::DeveloperIdInstaller);
    let p12 = identity.write_p12(dir.path());

    mdmsign()
        .current_dir(dir.path())
        .arg("pkg")
        .arg(&app)
        .arg("--p12")
        .arg(&p12)
        .arg("--no-timestamp")
        .env("MDMSIGN_P12_PASSWORD", &identity.password)
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Built and signed Demo-1.0-signed.pkg",
        ))
        .stderr(predicate::str::contains(
            "Package ID:  com.example.demo.pkg",
        ))
        .stderr(predicate::str::contains(
            "Installs to: /Applications/Demo.app",
        ));
    assert!(dir.path().join("Demo-1.0-signed.pkg").is_file());

    // Second run refuses to overwrite.
    mdmsign()
        .current_dir(dir.path())
        .arg("package")
        .arg(&app)
        .arg("--p12")
        .arg(&p12)
        .arg("--no-timestamp")
        .env("MDMSIGN_P12_PASSWORD", &identity.password)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("already exists"))
        .stderr(predicate::str::contains("--force"));
}

#[cfg(target_os = "macos")]
#[test]
fn pkg_uses_identifier_prefix_from_config() {
    let dir = tempfile::tempdir().unwrap();
    let app = testutil::make_test_app(dir.path(), "Demo", "com.example.demo", "1.0");
    let identity = testutil::TestIdentity::generate(mdmsign_core::CertKind::DeveloperIdInstaller);
    let p12 = identity.write_p12(dir.path());
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "[package]\nidentifier_prefix = \"org.acme.pkg\"\n").unwrap();

    mdmsign()
        .current_dir(dir.path())
        .arg("--config")
        .arg(&config)
        .arg("pkg")
        .arg(&app)
        .args(["-o", "out.pkg", "--no-timestamp", "--p12"])
        .arg(&p12)
        .env("MDMSIGN_P12_PASSWORD", &identity.password)
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Package ID:  org.acme.pkg.com.example.demo",
        ));
}
