//! Verifying flat installer packages.

use std::path::Path;

use crate::{
    Error, Result,
    verify::{Report, VerifyOptions},
};

/// Verifies a `.pkg`: signature, certificate type and chain, timestamp,
/// notarization (online unless `offline`), staple, and on macOS `spctl`.
pub fn verify(_path: &Path, _options: &VerifyOptions) -> Result<Report> {
    // TODO(pkg): implement with apple-xar's XarReader and apple-codesign.
    Err(Error::NotImplemented(".pkg verification"))
}
