//! `mdmsign staple`

use std::process::ExitCode;

use mdmsign_core::notarize;

use crate::cli::StapleArgs;

pub fn run(args: StapleArgs) -> anyhow::Result<ExitCode> {
    notarize::staple(&args.file)?;
    println!(
        "Stapled the notarization ticket to {}.",
        args.file.display()
    );
    Ok(ExitCode::SUCCESS)
}
