//! `mdmsign`: sign, notarize and verify macOS packages and configuration
//! profiles for MDM deployment.

mod cli;
mod commands;
mod output;

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    let cli = cli::Cli::parse();
    match commands::run(cli) {
        Ok(code) => code,
        Err(err) => output::report_error(&err),
    }
}
