//! Signing configuration profiles (`.mobileconfig`) as CMS SignedData.
//!
//! Two backends:
//! - [`NativeProfileSigner`]: the `cryptographic-message-syntax` crate, for
//!   `.p12` identities on any platform.
//! - [`SecurityCmsSigner`]: `security cms -S`, for Keychain identities on
//!   macOS.

use std::path::Path;

use crate::{
    Error, Result, SigningIdentity,
    sign::{SignOptions, Signer},
};

/// Errors specific to profile signing and verification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProfileError {
    #[error("the profile isn't a valid property list: {detail}")]
    InvalidPlist { detail: String },
}

impl ProfileError {
    pub fn hint(&self) -> Option<String> {
        match self {
            Self::InvalidPlist { .. } => Some(
                "Check the profile with `plutil -lint <file>` and fix any errors it reports."
                    .into(),
            ),
        }
    }
}

/// Signs profiles in-process with the `cryptographic-message-syntax` crate.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeProfileSigner;

impl Signer for NativeProfileSigner {
    fn name(&self) -> &'static str {
        "cms"
    }

    fn sign(
        &self,
        _input: &Path,
        _output: &Path,
        _identity: &SigningIdentity,
        _options: &SignOptions,
    ) -> Result<()> {
        // TODO(profile): build CMS SignedData with SignedDataBuilder.
        Err(Error::NotImplemented("native profile signing"))
    }
}

/// Signs profiles with `security cms -S` (macOS, Keychain identities).
#[derive(Clone, Copy, Debug, Default)]
pub struct SecurityCmsSigner;

impl Signer for SecurityCmsSigner {
    fn name(&self) -> &'static str {
        "security cms"
    }

    fn sign(
        &self,
        _input: &Path,
        _output: &Path,
        _identity: &SigningIdentity,
        _options: &SignOptions,
    ) -> Result<()> {
        // TODO(profile): shell out to security cms -S.
        Err(Error::NotImplemented("Keychain profile signing"))
    }
}

/// Whether the profile is already CMS-signed.
pub fn is_signed(_path: &Path) -> Result<bool> {
    // TODO(profile): detect a DER CMS ContentInfo.
    Err(Error::NotImplemented("detecting profile signatures"))
}
