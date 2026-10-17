//! Records the git commit mdmsign was built from, for `mdmsign --version`.
//!
//! Sets `MDMSIGN_COMMIT` to " (<short sha>)" or, when the commit isn't
//! known, to an empty string.

use std::{
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let sha = from_vcs_info(&manifest_dir).or_else(|| from_git(&manifest_dir));
    let suffix = sha
        .map(|sha| format!(" ({})", &sha[..sha.len().min(10)]))
        .unwrap_or_default();
    println!("cargo:rustc-env=MDMSIGN_COMMIT={suffix}");
}

/// `cargo package` records the commit in `.cargo_vcs_info.json`, so builds
/// from crates.io know it without a git checkout.
fn from_vcs_info(manifest_dir: &Path) -> Option<String> {
    let path = manifest_dir.join(".cargo_vcs_info.json");
    let info: serde_json::Value = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
    let sha = info["git"]["sha1"].as_str()?;
    sha.bytes()
        .all(|b| b.is_ascii_hexdigit())
        .then(|| sha.to_owned())
}

fn from_git(manifest_dir: &Path) -> Option<String> {
    // Only trust a repository that tracks this crate, not one that happens
    // to contain it (such as a home directory under git).
    git(manifest_dir, &["ls-files", "--error-unmatch", "build.rs"])?;

    // Rebuild when the checked-out commit changes. Cargo reruns on every
    // build if a watched file is missing, so skip ones that don't exist (a
    // branch can live only in packed-refs).
    let mut watch = vec!["HEAD".to_owned(), "packed-refs".to_owned()];
    watch.extend(git(manifest_dir, &["symbolic-ref", "-q", "HEAD"]));
    for name in watch {
        if let Some(path) = git(manifest_dir, &["rev-parse", "--git-path", &name]) {
            let path = manifest_dir.join(path);
            if path.exists() {
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }

    let sha = git(manifest_dir, &["rev-parse", "HEAD"])?;
    sha.bytes().all(|b| b.is_ascii_hexdigit()).then_some(sha)
}

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .ok()?;
    let text = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (output.status.success() && !text.is_empty()).then_some(text)
}
