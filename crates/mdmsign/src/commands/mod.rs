//! One module per subcommand.

mod certs;
mod creds;
mod docs;
mod notarize;
mod pkg;
mod sign;
mod staple;
mod verify;

use std::process::ExitCode;

use mdmsign_core::{config::Config, credentials::ProcessEnv};

use crate::cli::{Cli, Command};

pub fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    // These only describe the CLI, so a broken config file mustn't stop them.
    match cli.command {
        Command::Completions(args) => return docs::completions(args),
        Command::Man(args) => return docs::man(args),
        _ => {}
    }
    let config =
        Config::load(cli.config.as_deref(), &ProcessEnv).map_err(mdmsign_core::Error::from)?;
    match cli.command {
        Command::Sign(args) => sign::run(args, &config),
        Command::Pkg(args) => pkg::run(args, &config),
        Command::Notarize(args) => notarize::run(args, &config),
        Command::Staple(args) => staple::run(args),
        Command::Verify(args) => verify::run(args),
        Command::Certs(args) => certs::run(args, &config),
        Command::Completions(_) | Command::Man(_) => unreachable!("handled above"),
    }
}
