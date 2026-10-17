//! `mdmsign certs`

use std::process::ExitCode;

use mdmsign_core::{certs, config::Config};

use crate::{cli::CertsArgs, output};

pub fn run(args: CertsArgs, _config: &Config) -> anyhow::Result<ExitCode> {
    // TODO(certs): load --p12 (prompting for its password) and render a table.
    let entries = certs::list(!args.no_keychain, &[])?;
    if args.json {
        output::print_json(&entries)?;
    }
    Ok(ExitCode::SUCCESS)
}
