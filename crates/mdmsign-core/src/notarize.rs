//! Notarizing and stapling packages through the App Store Connect API.

use std::{path::Path, time::Duration};

use serde::Serialize;

use crate::{Error, Result, credentials::AscCredentials};

/// Errors from notarization and stapling.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NotarizeError {
    #[error("Apple rejected the submission {submission_id}")]
    Rejected { submission_id: String },
}

impl NotarizeError {
    pub fn hint(&self) -> Option<String> {
        match self {
            Self::Rejected { .. } => {
                Some("Read the notarization log printed above for the reasons.".into())
            }
        }
    }
}

/// Options for [`notarize`].
#[derive(Clone, Debug)]
pub struct NotarizeOptions {
    /// Wait for Apple's verdict instead of returning after upload.
    pub wait: bool,
    /// Staple the ticket after a successful verdict (requires `wait`).
    pub staple: bool,
    /// How long to wait for a verdict.
    pub timeout: Duration,
}

impl Default for NotarizeOptions {
    fn default() -> Self {
        Self {
            wait: true,
            staple: true,
            timeout: Duration::from_secs(30 * 60),
        }
    }
}

/// What [`notarize`] did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum NotarizeOutcome {
    /// Uploaded; not waiting for the verdict.
    Submitted { submission_id: String },
    /// Apple accepted the submission.
    Accepted {
        submission_id: String,
        stapled: bool,
    },
}

/// Submits a signed `.pkg` for notarization. `progress` receives
/// human-readable status lines.
pub fn notarize(
    _path: &Path,
    _credentials: &AscCredentials,
    _options: &NotarizeOptions,
    _progress: &mut dyn FnMut(&str),
) -> Result<NotarizeOutcome> {
    // TODO(notarize): use apple_codesign::notarization::Notarizer.
    Err(Error::NotImplemented("notarize"))
}

/// Downloads the notarization ticket for a `.pkg` and staples it.
pub fn staple(_path: &Path) -> Result<()> {
    // TODO(notarize): use apple_codesign::stapling::Stapler.
    Err(Error::NotImplemented("staple"))
}
