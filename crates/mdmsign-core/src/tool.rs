//! Running Apple's command-line tools (`productsign`, `security`, `pkgutil`,
//! `spctl`, ...).
//!
//! Never pass secrets as arguments: they are visible to other processes and
//! may be echoed in error messages.

use std::{
    ffi::OsStr,
    process::{Command, Output},
};

/// Errors from running an external tool.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ToolError {
    #[error("`{tool}` was not found")]
    NotFound { tool: String },

    #[error("couldn't run `{tool}`: {source}")]
    Spawn {
        tool: String,
        #[source]
        source: std::io::Error,
    },

    #[error("`{tool}` failed{}: {}", status.map(|s| format!(" (exit status {s})")).unwrap_or_default(), summarize(stderr))]
    Failed {
        tool: String,
        status: Option<i32>,
        stderr: String,
    },
}

impl ToolError {
    pub fn hint(&self) -> Option<String> {
        match self {
            Self::NotFound { tool } => Some(format!(
                "`{tool}` ships with macOS. If you're on macOS, install the Xcode Command Line Tools with `xcode-select --install`. On other platforms, use a .p12 file (--p12) so mdmsign can sign without Apple's tools."
            )),
            Self::Spawn { .. } => None,
            Self::Failed { .. } => None,
        }
    }
}

fn summarize(stderr: &str) -> String {
    let trimmed = stderr.trim();
    if trimmed.is_empty() {
        "no error output".into()
    } else {
        trimmed.to_string()
    }
}

/// Runs `tool` with `args` and returns its output whatever the exit status.
pub fn run_unchecked<I, S>(tool: &str, args: I) -> Result<Output, ToolError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(tool).args(args).output().map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            ToolError::NotFound {
                tool: tool.to_string(),
            }
        } else {
            ToolError::Spawn {
                tool: tool.to_string(),
                source,
            }
        }
    })
}

/// Runs `tool` with `args` and returns its output, or [`ToolError::Failed`]
/// if it exits unsuccessfully.
pub fn run<I, S>(tool: &str, args: I) -> Result<Output, ToolError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = run_unchecked(tool, args)?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(ToolError::Failed {
            tool: tool.to_string(),
            status: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}
