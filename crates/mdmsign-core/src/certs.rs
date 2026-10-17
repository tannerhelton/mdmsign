//! Listing signing identities and flagging the wrong certificate types.

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::{ArtifactKind, CertKind, Error, Result, SigningIdentity};

/// One identity, with what it can and can't sign.
#[derive(Clone, Debug, Serialize)]
pub struct CertEntry {
    /// `keychain` or the `.p12` it came from.
    pub source: String,
    pub name: String,
    pub sha1: String,
    pub kind: CertKind,
    pub team_id: Option<String>,
    pub not_after: Option<DateTime<Utc>>,
    /// True if it can sign at least one supported file type now.
    pub usable: bool,
    /// File types this identity can sign.
    pub can_sign: Vec<ArtifactKind>,
    /// Problems and advice, e.g. "can't sign .pkg; you need Developer ID Installer".
    pub notes: Vec<String>,
}

/// Lists Keychain identities (on macOS) plus `extra` identities such as a
/// `.p12` given on the command line.
pub fn list(_include_keychain: bool, _extra: &[SigningIdentity]) -> Result<Vec<CertEntry>> {
    // TODO(certs): combine keychain::list_identities with classification.
    Err(Error::NotImplemented("certs"))
}
