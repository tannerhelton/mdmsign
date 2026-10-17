//! `mdmsign sign`

use std::process::ExitCode;

use mdmsign_core::{
    ArtifactKind,
    config::Config,
    sign::{self, Backend, Output, SignOptions},
};

use crate::{
    cli::{BackendArg, SignArgs, SigningFlags},
    commands::creds,
};

/// Builds signing options from flags, falling back to the config file.
pub fn sign_options(
    flags: &SigningFlags,
    force: bool,
    resign: bool,
    config: &Config,
) -> SignOptions {
    let defaults = SignOptions::default();
    SignOptions {
        timestamp: !flags.no_timestamp && config.signing.timestamp.unwrap_or(true),
        timestamp_url: flags
            .timestamp_url
            .clone()
            .or_else(|| config.signing.timestamp_url.clone())
            .unwrap_or(defaults.timestamp_url),
        backend: match flags.backend {
            Some(BackendArg::Auto) => Backend::Auto,
            Some(BackendArg::Native) => Backend::Native,
            Some(BackendArg::Apple) => Backend::Apple,
            None => config.signing.backend.unwrap_or_default(),
        },
        resign,
        force,
    }
}

/// Tells the admin about a possible Keychain prompt.
pub fn announce_keychain(identity: &mdmsign_core::SigningIdentity) {
    if identity.is_keychain() {
        eprintln!(
            "macOS may ask you to allow access to the signing key; choose \"Always Allow\" to skip this next time."
        );
    }
}

pub fn run(args: SignArgs, config: &Config) -> anyhow::Result<ExitCode> {
    // Check the input before credentials, so a typo in the path doesn't cost
    // a Keychain lookup or a password prompt.
    let kind = ArtifactKind::detect(&args.file)?;
    let identity = creds::load_identity(&args.signing.identity, config)?;
    let options = sign_options(&args.signing, args.force, args.resign, config);
    let output = match (args.output, args.in_place) {
        (Some(path), _) => Output::Path(path),
        (None, true) => Output::InPlace,
        (None, false) => Output::Default,
    };

    eprintln!(
        "Signing {} with \"{}\"",
        crate::output::clean_line(&args.file.display().to_string()),
        crate::output::clean_line(&identity.common_name())
    );
    announce_keychain(&identity);
    if options.timestamp && kind == ArtifactKind::FlatPackage {
        eprintln!("Adding a secure timestamp (needs an internet connection)…");
    }

    let outcome = sign::sign_file(&args.file, &output, &identity, &options)?;

    for warning in &outcome.warnings {
        eprintln!("warning: {}", crate::output::clean(warning));
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
