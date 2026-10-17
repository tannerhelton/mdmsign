//! `mdmsign completions` and `mdmsign man`, generated from the clap
//! definition so they never drift from `--help`.

use std::{
    fs,
    io::{self, Write},
    process::ExitCode,
};

use anyhow::Context;
use clap::CommandFactory;

use crate::cli::{Cli, CompletionsArgs, ManArgs};

pub fn completions(args: CompletionsArgs) -> anyhow::Result<ExitCode> {
    // Render into memory first: clap_complete panics if a write fails, and
    // stdout may be a closed pipe.
    let mut script = Vec::new();
    clap_complete::generate(args.shell, &mut Cli::command(), "mdmsign", &mut script);
    io::stdout()
        .write_all(&script)
        .context("couldn't write the completion script")?;
    Ok(ExitCode::SUCCESS)
}

pub fn man(args: ManArgs) -> anyhow::Result<ExitCode> {
    let Some(dir) = args.out_dir else {
        let mut page = Vec::new();
        clap_mangen::Man::new(Cli::command()).render(&mut page)?;
        io::stdout()
            .write_all(&page)
            .context("couldn't write the man page")?;
        return Ok(ExitCode::SUCCESS);
    };
    fs::create_dir_all(&dir)
        .and_then(|()| clap_mangen::generate_to(Cli::command(), &dir))
        .with_context(|| format!("couldn't write man pages to {}", dir.display()))?;
    eprintln!("Wrote man pages to {}.", dir.display());
    Ok(ExitCode::SUCCESS)
}
