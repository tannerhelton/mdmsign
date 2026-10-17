//! `mdmsign notarize`

use std::{process::ExitCode, time::Duration};

use mdmsign_core::{
    config::Config,
    credentials::{self, AscArgs, ProcessEnv},
    notarize::{self, NotarizeOptions, NotarizeOutcome},
};

use crate::{cli::NotarizeArgs, output};

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
        timeout: Duration::from_secs(config.notarize.timeout_minutes.unwrap_or(args.timeout) * 60),
    };
    let outcome = notarize::notarize(&args.file, &creds, &options, &mut |line| {
        eprintln!("{line}")
    })?;
    if args.json {
        output::print_json(&outcome)?;
        return Ok(ExitCode::SUCCESS);
    }
    match outcome {
        NotarizeOutcome::Submitted { submission_id } => {
            println!(
                "Submitted {} (submission {submission_id}).",
                args.file.display()
            );
            eprintln!(
                "When Apple accepts it, run `mdmsign staple {}`.",
                args.file.display()
            );
        }
        NotarizeOutcome::Accepted {
            submission_id,
            stapled,
        } => {
            println!(
                "Notarized {} (submission {submission_id}).",
                args.file.display()
            );
            if stapled {
                println!("Ticket stapled.");
            } else {
                eprintln!(
                    "Not stapled. Run `mdmsign staple {}` before uploading.",
                    args.file.display()
                );
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}
