//! `mdmsign sign`

use std::process::ExitCode;

use mdmsign_core::{
    ArtifactKind,
    config::Config,
    sign::{self, Backend, Output, SignOptions},
};

use crate::{
    cli::{BackendArg, SignArgs},
    commands::creds,
};

pub fn run(args: SignArgs, config: &Config) -> anyhow::Result<ExitCode> {
    // Check the input before credentials, so a typo in the path doesn't cost
    // a Keychain lookup or a password prompt.
    let kind = ArtifactKind::detect(&args.file)?;
    let identity = creds::load_identity(&args.identity, config)?;

    let defaults = SignOptions::default();
    let options = SignOptions {
        timestamp: !args.no_timestamp && config.signing.timestamp.unwrap_or(true),
        timestamp_url: args
            .timestamp_url
            .or_else(|| config.signing.timestamp_url.clone())
            .unwrap_or(defaults.timestamp_url),
        backend: match args.backend {
            Some(BackendArg::Auto) => Backend::Auto,
            Some(BackendArg::Native) => Backend::Native,
            Some(BackendArg::Apple) => Backend::Apple,
            None => config.signing.backend.unwrap_or_default(),
        },
        resign: args.resign,
        force: args.force,
    };
    let output = match (args.output, args.in_place) {
        (Some(path), _) => Output::Path(path),
        (None, true) => Output::InPlace,
        (None, false) => Output::Default,
    };

    eprintln!(
        "Signing {} with \"{}\"",
        args.file.display(),
        identity.common_name()
    );
    if identity.is_keychain() {
        eprintln!(
            "macOS may ask you to allow access to the signing key; choose \"Always Allow\" to skip this next time."
        );
    }
    if options.timestamp && kind == ArtifactKind::FlatPackage {
        eprintln!("Adding a secure timestamp (needs an internet connection)…");
    }

    let outcome = sign::sign_file(&args.file, &output, &identity, &options)?;

    for warning in &outcome.warnings {
        eprintln!("warning: {warning}");
    }
    println!(
        "Signed {} using {}",
        outcome.output.display(),
        outcome.backend
    );
    match outcome.kind {
        ArtifactKind::FlatPackage => {
            eprintln!(
                "Next: `mdmsign notarize {}` (recommended), then `mdmsign verify` before uploading.",
                outcome.output.display()
            );
        }
        ArtifactKind::ConfigurationProfile => {
            eprintln!(
                "Next: `mdmsign verify {}`, then upload it to your MDM.",
                outcome.output.display()
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}
