//! Signing flat installer packages (`.pkg`).
//!
//! Two backends:
//! - [`NativePkgSigner`]: apple-codesign's XAR signer, for `.p12` identities
//!   on any platform.
//! - [`ProductsignSigner`]: Apple's `productsign`, for Keychain identities on
//!   macOS.

use std::path::Path;

use crate::{
    Error, Result, SigningIdentity,
    sign::{SignOptions, Signer},
};

/// Errors specific to `.pkg` signing and verification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PkgError {
    #[error("the package is malformed: {detail}")]
    Malformed { detail: String },
}

impl PkgError {
    pub fn hint(&self) -> Option<String> {
        match self {
            Self::Malformed { .. } => {
                Some("Rebuild the package with `pkgbuild` or `productbuild` and try again.".into())
            }
        }
    }
}

/// Signs packages in-process with apple-codesign.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativePkgSigner;

impl Signer for NativePkgSigner {
    fn name(&self) -> &'static str {
        "apple-codesign"
    }

    fn sign(
        &self,
        _input: &Path,
        _output: &Path,
        _identity: &SigningIdentity,
        _options: &SignOptions,
    ) -> Result<()> {
        // TODO(pkg): sign with apple_codesign::UnifiedSigner::sign_xar.
        Err(Error::NotImplemented("native .pkg signing"))
    }
}

/// Signs packages with `/usr/bin/productsign` (macOS, Keychain identities).
#[derive(Clone, Copy, Debug, Default)]
pub struct ProductsignSigner;

impl Signer for ProductsignSigner {
    fn name(&self) -> &'static str {
        "productsign"
    }

    fn sign(
        &self,
        _input: &Path,
        _output: &Path,
        _identity: &SigningIdentity,
        _options: &SignOptions,
    ) -> Result<()> {
        // TODO(pkg): shell out to productsign --sign <sha1> [--timestamp].
        Err(Error::NotImplemented("productsign .pkg signing"))
    }
}

/// Whether the package already has a signature.
pub fn is_signed(_path: &Path) -> Result<bool> {
    // TODO(pkg): read the XAR table of contents and look for <signature>.
    Err(Error::NotImplemented("detecting .pkg signatures"))
}
