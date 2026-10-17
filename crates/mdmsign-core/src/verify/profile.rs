//! Verifying configuration profiles.

use std::path::Path;

use crate::{
    Error, Result,
    verify::{Report, VerifyOptions},
};

/// Verifies a `.mobileconfig`: signed or not, CMS signature, certificate,
/// chain, and that the payload is a well-formed configuration profile.
pub fn verify(_path: &Path, _options: &VerifyOptions) -> Result<Report> {
    // TODO(profile): implement with cryptographic-message-syntax's SignedData.
    Err(Error::NotImplemented("profile verification"))
}
