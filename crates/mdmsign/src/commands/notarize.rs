//! `mdmsign notarize`

use std::{process::ExitCode, time::Duration};

use mdmsign_core::{
    Error,
    config::Config,
    credentials::{self, AscArgs, ProcessEnv},
    notarize::{self, NotarizeError, NotarizeOptions, NotarizeOutcome},
};

use crate::{cli::NotarizeArgs, output};

/// Minutes to wait for a verdict when neither the flag nor the config says.
const DEFAULT_TIMEOUT_MINUTES: u64 = 30;

pub fn run(args: NotarizeArgs, config: &Config) -> anyhow::Result<ExitCode> {
    let asc = AscArgs {
        key_path: args.asc.key,
        key_id: args.asc.key_id,
        issuer_id: args.asc.issuer,
    };
    let creds = credentials::load_asc_credentials(&asc, &ProcessEnv, config)
        .map_err(mdmsign_core::Error::from)?;
    let options = NotarizeOptions {
        wait: !args.no_wait,
        staple: !args.no_staple && !args.no_wait,
        timeout: resolve_timeout(args.timeout, config),
    };
    let file = args.file.display().to_string();
    let result = notarize::notarize(&args.file, &creds, &options, &mut |line| {
        eprintln!("{line}")
    });
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(err) => {
            if args.json
                && let Error::Notarize(notarize_err) = &err
                && let Some(value) = failure_json(notarize_err)
            {
                output::print_json(&value)?;
            }
            return Err(err.into());
        }
    };
    if args.json {
        output::print_json(&outcome)?;
        return Ok(ExitCode::SUCCESS);
    }
    match outcome {
        NotarizeOutcome::Submitted { submission_id } => {
            println!("Submitted {file} for notarization (submission {submission_id}).");
            eprintln!(
                "Apple usually finishes within minutes. Then run `mdmsign staple {file}` before uploading it to your MDM."
            );
        }
        NotarizeOutcome::Accepted {
            submission_id,
            stapled,
            ..
        } => {
            println!("Notarized {file} (submission {submission_id}).");
            if stapled {
                println!("Ticket stapled; the package is ready for your MDM.");
                eprintln!("Next: `mdmsign verify {file}` to double-check before uploading.");
            } else if options.staple {
                eprintln!(
                    "Not stapled yet. Run `mdmsign staple {file}` in a few minutes, before uploading it."
                );
            } else {
                eprintln!(
                    "Not stapled (--no-staple). Run `mdmsign staple {file}` before uploading it."
                );
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// `--timeout` beats `timeout_minutes` in the config file, which beats the
/// default.
fn resolve_timeout(flag_minutes: Option<u64>, config: &Config) -> Duration {
    let minutes = flag_minutes
        .or(config.notarize.timeout_minutes)
        .unwrap_or(DEFAULT_TIMEOUT_MINUTES);
    Duration::from_secs(minutes.saturating_mul(60))
}

/// A machine-readable description of a failed submission, so `--json`
/// users get the submission ID and Apple's issues on stdout.
fn failure_json(err: &NotarizeError) -> Option<serde_json::Value> {
    match err {
        NotarizeError::Rejected {
            submission_id,
            status,
            summary,
            issues,
        } => Some(serde_json::json!({
            "status": status.to_lowercase(),
            "submission_id": submission_id,
            "summary": summary,
            "issues": issues,
        })),
        NotarizeError::Timeout { submission_id, .. } => Some(serde_json::json!({
            "status": "in-progress",
            "submission_id": submission_id,
        })),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use mdmsign_core::notarize::NotaryIssue;

    use super::*;

    #[test]
    fn timeout_flag_beats_config_beats_default() {
        let mut config = Config::default();
        assert_eq!(resolve_timeout(None, &config), Duration::from_secs(30 * 60));
        config.notarize.timeout_minutes = Some(45);
        assert_eq!(resolve_timeout(None, &config), Duration::from_secs(45 * 60));
        assert_eq!(
            resolve_timeout(Some(5), &config),
            Duration::from_secs(5 * 60)
        );
    }

    #[test]
    fn failure_json_shapes() {
        let rejected = NotarizeError::Rejected {
            submission_id: "abc".into(),
            status: "Invalid".into(),
            summary: Some("Archive contains critical validation errors".into()),
            issues: vec![NotaryIssue {
                severity: "error".into(),
                path: Some("a.pkg".into()),
                message: "The signature does not include a secure timestamp.".into(),
                doc_url: None,
                architecture: None,
            }],
        };
        let value = failure_json(&rejected).unwrap();
        assert_eq!(value["status"], "invalid");
        assert_eq!(value["submission_id"], "abc");
        assert_eq!(value["issues"][0]["severity"], "error");

        let timeout = NotarizeError::Timeout {
            submission_id: "abc".into(),
            path: PathBuf::from("a.pkg"),
            waited: Duration::from_secs(60),
        };
        assert_eq!(failure_json(&timeout).unwrap()["status"], "in-progress");

        let unsigned = NotarizeError::Unsigned {
            path: PathBuf::from("a.pkg"),
        };
        assert!(failure_json(&unsigned).is_none());
    }
}
