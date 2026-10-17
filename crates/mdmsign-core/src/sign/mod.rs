//! Signing files.
//!
//! [`sign_file`] is the entry point. It detects the file type, checks the
//! identity fits, picks a [`Signer`] backend, signs into a temporary file
//! next to the destination, verifies the result, and only then moves it into
//! place, so a failed run never leaves a half-written file behind.

pub mod pkg;
pub mod profile;

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{
    ArtifactKind, Error, Result, SigningIdentity,
    error::io_error,
    verify::{self, CheckId, Status, VerifyOptions},
};

/// Apple's RFC 3161 timestamp server.
pub const APPLE_TIMESTAMP_URL: &str = "http://timestamp.apple.com/ts01";

/// Which signing implementation to use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Backend {
    /// Apple's tools for Keychain identities, native Rust for `.p12` files.
    #[default]
    Auto,
    /// Native Rust signing (apple-codesign / CMS). Needs a `.p12` identity.
    Native,
    /// Apple's tools (`productsign`, `security cms`). Needs macOS and a
    /// Keychain identity.
    Apple,
}

/// Options for signing.
#[derive(Clone, Debug)]
pub struct SignOptions {
    /// Add a secure timestamp to `.pkg` signatures. Required for
    /// notarization; needs internet. Profiles are never timestamped: macOS
    /// ignores timestamps on them.
    pub timestamp: bool,
    pub timestamp_url: String,
    pub backend: Backend,
    /// Replace an existing signature instead of refusing.
    pub resign: bool,
    /// Overwrite an existing output file.
    pub force: bool,
}

impl Default for SignOptions {
    fn default() -> Self {
        Self {
            timestamp: true,
            timestamp_url: APPLE_TIMESTAMP_URL.to_string(),
            backend: Backend::Auto,
            resign: false,
            force: false,
        }
    }
}

/// Where to write the signed file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum Output {
    /// `<name>-signed.<ext>` next to the input.
    #[default]
    Default,
    /// Replace the input file.
    InPlace,
    Path(PathBuf),
}

/// What [`sign_file`] did.
#[derive(Clone, Debug, Serialize)]
pub struct SignOutcome {
    pub input: PathBuf,
    pub output: PathBuf,
    pub kind: ArtifactKind,
    /// The backend that signed, e.g. `apple-codesign` or `productsign`.
    pub backend: &'static str,
    pub signer: String,
    pub timestamped: bool,
    /// Non-fatal advice, e.g. about the certificate choice.
    pub warnings: Vec<String>,
}

/// A signing implementation for one kind of file.
pub trait Signer {
    /// Short name shown to the user, e.g. `productsign`.
    fn name(&self) -> &'static str;

    /// Signs `input` and writes the result to `output`.
    ///
    /// `output` is a path in a fresh temporary directory next to the final
    /// destination and doesn't exist yet. `input` must not be modified. If
    /// `input` is already signed, [`sign_file`] has already checked that
    /// `options.resign` is set; the signer must replace the old signature.
    fn sign(
        &self,
        input: &Path,
        output: &Path,
        identity: &SigningIdentity,
        options: &SignOptions,
    ) -> Result<()>;
}

/// Picks the signer for `kind` given the identity and requested backend.
pub fn signer_for(
    kind: ArtifactKind,
    identity: &SigningIdentity,
    backend: Backend,
) -> Result<Box<dyn Signer>> {
    let backend = resolve_backend(identity, backend)?;
    Ok(match (kind, backend) {
        (ArtifactKind::FlatPackage, Backend::Apple) => Box::new(pkg::ProductsignSigner),
        (ArtifactKind::FlatPackage, _) => Box::new(pkg::NativePkgSigner),
        (ArtifactKind::ConfigurationProfile, Backend::Apple) => {
            Box::new(profile::SecurityCmsSigner)
        }
        (ArtifactKind::ConfigurationProfile, _) => Box::new(profile::NativeProfileSigner),
    })
}

fn resolve_backend(identity: &SigningIdentity, backend: Backend) -> Result<Backend> {
    match (backend, identity.is_keychain()) {
        (Backend::Auto, true) => Ok(Backend::Apple),
        (Backend::Auto, false) => Ok(Backend::Native),
        (Backend::Native, true) => Err(Error::BackendMismatch {
            backend: "native",
            reason: "it needs the private key in memory, but this identity's key is in the macOS Keychain".into(),
            hint: "Drop --backend native to sign with Apple's tools, or export the identity as a .p12 and pass --p12.".into(),
        }),
        (Backend::Apple, false) => Err(Error::BackendMismatch {
            backend: "apple",
            reason: "Apple's signing tools only use identities installed in the macOS Keychain".into(),
            hint: "Drop --backend apple to sign the .p12 natively, or import the .p12 into your Keychain and pass --identity.".into(),
        }),
        (b, _) => Ok(b),
    }
}

/// Whether the file already carries a signature.
pub fn is_signed(path: &Path, kind: ArtifactKind) -> Result<bool> {
    match kind {
        ArtifactKind::FlatPackage => pkg::is_signed(path),
        ArtifactKind::ConfigurationProfile => profile::is_signed(path),
    }
}

/// The default output path: `<dir>/<stem>-signed.<ext>`.
pub fn default_output_path(input: &Path, kind: ArtifactKind) -> PathBuf {
    let stem = input
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = input
        .extension()
        .map(|e| e.to_string_lossy().into_owned())
        .unwrap_or_else(|| kind.extension().to_string());
    input.with_file_name(format!("{stem}-signed.{ext}"))
}

/// Signs `input`. See the module docs for the steps.
pub fn sign_file(
    input: &Path,
    output: &Output,
    identity: &SigningIdentity,
    options: &SignOptions,
) -> Result<SignOutcome> {
    let kind = ArtifactKind::detect(input)?;
    let mut warnings = Vec::new();
    if let Some(warning) = identity.check_for(kind, chrono::Utc::now())? {
        warnings.push(warning);
    }

    if is_signed(input, kind)? && !options.resign {
        return Err(Error::AlreadySigned {
            path: input.to_path_buf(),
            kind,
        });
    }

    let destination = match output {
        Output::Default => default_output_path(input, kind),
        Output::InPlace => input.to_path_buf(),
        Output::Path(path) => path.clone(),
    };
    let in_place = same_file(input, &destination);
    if destination.exists() && !in_place && !options.force {
        return Err(Error::OutputExists(destination));
    }

    let signer = signer_for(kind, identity, options.backend)?;

    let dir = match destination.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let staging = tempfile::Builder::new()
        .prefix(".mdmsign-")
        .tempdir_in(&dir)
        .map_err(io_error("create a temporary directory in", &dir))?;
    let file_name = destination
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_else(|| "signed".into());
    let staged = staging.path().join(file_name);

    signer.sign(input, &staged, identity, options)?;

    let report = verify::verify_file(&staged, &VerifyOptions::post_sign())?;
    if let Some(check) = report.check(CheckId::SignatureValid)
        && check.status == Status::Fail
    {
        return Err(Error::PostSignVerification {
            detail: check.summary.clone(),
        });
    }

    std::fs::rename(&staged, &destination).map_err(io_error("write", &destination))?;

    Ok(SignOutcome {
        input: input.to_path_buf(),
        output: destination,
        kind,
        backend: signer.name(),
        signer: identity.common_name(),
        timestamped: options.timestamp && kind == ArtifactKind::FlatPackage,
        warnings,
    })
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_output_keeps_extension_case() {
        assert_eq!(
            default_output_path(Path::new("/tmp/My App.pkg"), ArtifactKind::FlatPackage),
            PathBuf::from("/tmp/My App-signed.pkg")
        );
        assert_eq!(
            default_output_path(
                Path::new("wifi.mobileconfig"),
                ArtifactKind::ConfigurationProfile
            ),
            PathBuf::from("wifi-signed.mobileconfig")
        );
    }
}
