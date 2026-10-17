//! End-to-end tests of the `mdmsign` binary that don't need signing to work.

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

#[test]
fn help_lists_commands_and_env_vars() {
    mdmsign()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("sign"))
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("MDMSIGN_P12_PASSWORD"));
}

#[test]
fn sign_without_identity_explains_options() {
    let dir = tempfile::tempdir().unwrap();
    let profile = mdmsign_core::testutil::write_sample_profile(dir.path());
    mdmsign()
        .arg("sign")
        .arg(&profile)
        .assert()
        .code(2)
        .stderr(predicate::str::contains(
            "error: no signing identity was given",
        ))
        .stderr(predicate::str::contains("fix:"))
        .stderr(predicate::str::contains("--p12"));
}

#[test]
fn sign_with_wrong_p12_password_fails_clearly() {
    let dir = tempfile::tempdir().unwrap();
    let profile = mdmsign_core::testutil::write_sample_profile(dir.path());
    let identity = mdmsign_core::testutil::TestIdentity::generate(
        mdmsign_core::CertKind::DeveloperIdApplication,
    );
    let p12 = identity.write_p12(dir.path());
    mdmsign()
        .arg("sign")
        .arg(&profile)
        .arg("--p12")
        .arg(&p12)
        .env("MDMSIGN_P12_PASSWORD", "not-the-password")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("password"))
        .stderr(predicate::str::contains("not-the-password").not());
}

#[test]
fn sign_checks_the_file_before_credentials() {
    mdmsign()
        .args(["sign", "/definitely/not/here.pkg"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("file not found"))
        .stderr(predicate::str::contains("signing identity").not());
}

#[test]
fn verify_missing_file() {
    mdmsign()
        .args(["verify", "/definitely/not/here.pkg"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("file not found"));
}

#[test]
fn explicit_config_must_exist() {
    mdmsign()
        .args(["--config", "/definitely/not/here.toml", "verify", "x.pkg"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("config file not found"));
}

#[test]
fn config_with_password_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "[signing]\np12_password = \"hunter2\"\n").unwrap();
    mdmsign()
        .arg("--config")
        .arg(&config)
        .args(["verify", "x.pkg"])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("contains a secret"))
        .stderr(predicate::str::contains("hunter2").not());
}

#[test]
fn completions_print_a_script_for_each_shell() {
    for (shell, marker) in [
        ("bash", "complete -F _mdmsign"),
        ("zsh", "#compdef mdmsign"),
        ("fish", "complete -c mdmsign"),
        ("powershell", "Register-ArgumentCompleter"),
        ("elvish", "edit:completion:arg-completer[mdmsign]"),
    ] {
        mdmsign()
            .args(["completions", shell])
            .assert()
            .success()
            .stdout(predicate::str::contains(marker))
            .stdout(predicate::str::contains("notarize"));
    }
}

#[test]
fn completions_and_man_ignore_a_broken_config() {
    mdmsign()
        .args([
            "--config",
            "/definitely/not/here.toml",
            "completions",
            "zsh",
        ])
        .assert()
        .success();
    mdmsign()
        .args(["--config", "/definitely/not/here.toml", "man"])
        .assert()
        .success();
}

#[test]
fn man_prints_the_top_level_page() {
    mdmsign()
        .arg("man")
        .assert()
        .success()
        .stdout(predicate::str::contains(".TH mdmsign 1"))
        .stdout(predicate::str::contains("mdmsign\\-sign(1)"));
}

#[test]
fn man_out_dir_writes_a_page_per_command() {
    let dir = tempfile::tempdir().unwrap();
    let out = dir.path().join("man1");
    mdmsign()
        .args(["man", "--out-dir"])
        .arg(&out)
        .assert()
        .success();
    for page in ["mdmsign.1", "mdmsign-sign.1", "mdmsign-verify.1"] {
        let text = std::fs::read_to_string(out.join(page)).unwrap();
        assert!(text.contains(".TH "), "{page} isn't a man page");
    }
}

#[test]
fn version_includes_the_commit_when_known() {
    let commit = env!("MDMSIGN_COMMIT");
    // Empty, or " (<10 hex digits>)" (see build.rs).
    if let Some(sha) = commit.strip_prefix(" (").and_then(|s| s.strip_suffix(')')) {
        assert_eq!(sha.len(), 10, "{commit:?}");
        assert!(sha.bytes().all(|b| b.is_ascii_hexdigit()), "{commit:?}");
    } else {
        assert_eq!(commit, "");
    }
    mdmsign()
        .arg("--version")
        .assert()
        .success()
        .stdout(format!("mdmsign {}{commit}\n", env!("CARGO_PKG_VERSION")));
}
