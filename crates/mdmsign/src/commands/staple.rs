//! `mdmsign staple`

use std::process::ExitCode;

use mdmsign_core::notarize::{self, StapleOutcome};

use crate::{cli::StapleArgs, output};

pub fn run(args: StapleArgs) -> anyhow::Result<ExitCode> {
    let file = args.file.display().to_string();
    if !args.json {
        eprintln!("Looking up the notarization ticket for {file} with Apple…");
    }
    let outcome = notarize::staple(&args.file)?;
    if args.json {
        output::print_json(&serde_json::json!({ "status": outcome }))?;
        return Ok(ExitCode::SUCCESS);
    }
    match outcome {
        StapleOutcome::Stapled => println!("Stapled the notarization ticket to {file}."),
        StapleOutcome::AlreadyStapled => {
            println!("{file} already has its notarization ticket stapled; nothing to do.")
        }
    }
    eprintln!("Next: `mdmsign verify {file}`, then upload it to your MDM.");
    Ok(ExitCode::SUCCESS)
}
