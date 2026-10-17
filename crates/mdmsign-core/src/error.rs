//! Error types.
//!
//! Every error answers two questions for the admin: what went wrong (the
//! `Display` message) and what to do about it ([`Error::hint`]). Each area
//! owns its own error enum so it can grow without touching the others.

use std::path::PathBuf;

use crate::{
    ArtifactKind, config::ConfigError, credentials::CredentialError, notarize::NotarizeError,
    sign::pkg::PkgError, sign::profile::ProfileError, tool::ToolError,
};

/// Result type used throughout the library.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Any error mdmsign can report.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("file not found: {}", .0.display())]
    FileNotFound(PathBuf),

    #[error("couldn't {action} {}: {source}", path.display())]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("{} isn't a file mdmsign can handle: {detail}", path.display())]
    UnsupportedFile {
        path: PathBuf,
        detail: String,
        hint: Option<String>,
    },

    #[error("output file already exists: {}", .0.display())]
    OutputExists(PathBuf),

    #[error("{} is already signed", path.display())]
    AlreadySigned { path: PathBuf, kind: ArtifactKind },

    #[error("the {backend} backend can't use this identity: {reason}")]
    BackendMismatch {
        backend: &'static str,
        reason: String,
        hint: String,
    },

    #[error("signing finished but the result didn't verify: {detail}")]
    PostSignVerification { detail: String },

    #[error(transparent)]
    Credential(#[from] CredentialError),

    #[error(transparent)]
    Config(#[from] ConfigError),

    #[error(transparent)]
    Tool(#[from] ToolError),

    #[error(transparent)]
    Pkg(#[from] PkgError),

    #[error(transparent)]
    Profile(#[from] ProfileError),

    #[error(transparent)]
    Notarize(#[from] NotarizeError),

    #[error("{0} isn't implemented yet")]
    NotImplemented(&'static str),
}

impl Error {
    /// Advice for the admin: what to do next to fix this error.
    pub fn hint(&self) -> Option<String> {
        match self {
            Self::FileNotFound(_) => Some("Check the path and try again.".into()),
            Self::Io { .. } => {
                Some("Check that the file exists and that you have permission to read and write it.".into())
            }
            Self::UnsupportedFile { hint, .. } => hint.clone().or_else(|| {
                Some("mdmsign handles flat installer packages (.pkg) and configuration profiles (.mobileconfig).".into())
            }),
            Self::OutputExists(_) => Some(
                "Pass --force to replace it, --in-place to sign the input file itself, or -o to choose another path."
                    .into(),
            ),
            Self::AlreadySigned { kind, .. } => Some(match kind {
                ArtifactKind::ConfigurationProfile => {
                    "Pass --resign to strip the existing signature and sign it again.".into()
                }
                ArtifactKind::FlatPackage => {
                    "Pass --resign to replace the existing signature. Note that re-signing invalidates any notarization ticket, so notarize again afterwards.".into()
                }
            }),
            Self::BackendMismatch { hint, .. } => Some(hint.clone()),
            Self::PostSignVerification { .. } => Some(
                "The signed file was not saved. Run `mdmsign verify` on the original file and report a bug if this keeps happening."
                    .into(),
            ),
            Self::Credential(e) => e.hint(),
            Self::Config(e) => e.hint(),
            Self::Tool(e) => e.hint(),
            Self::Pkg(e) => e.hint(),
            Self::Profile(e) => e.hint(),
            Self::Notarize(e) => e.hint(),
            Self::NotImplemented(_) => {
                Some("This command is planned but not built yet. Watch the changelog for updates.".into())
            }
        }
    }

    /// True if the error is about how mdmsign was invoked or configured
    /// (missing or wrong credentials, a bad config file) rather than about
    /// the file being processed. The CLI exits with status 2 for these.
    pub fn is_usage_error(&self) -> bool {
        matches!(
            self,
            Self::Credential(_) | Self::Config(_) | Self::BackendMismatch { .. }
        )
    }
}

/// Shorthand for mapping an [`std::io::Error`] to [`Error::Io`].
pub(crate) fn io_error(
    action: &'static str,
    path: impl Into<PathBuf>,
) -> impl FnOnce(std::io::Error) -> Error {
    let path = path.into();
    move |source| {
        if source.kind() == std::io::ErrorKind::NotFound && action == "read" {
            Error::FileNotFound(path)
        } else {
            Error::Io {
                action,
                path,
                source,
            }
        }
    }
}
