//! `mdmsign pkg`

use std::{path::PathBuf, process::ExitCode};

use mdmsign_core::{
    app_pkg::{self, AppInfo, PackageOptions},
    config::Config,
};

use crate::{
    cli::PkgArgs,
    commands::{
        creds,
        sign::{announce_keychain, sign_options},
    },
};

pub fn run(args: PkgArgs, config: &Config) -> anyhow::Result<ExitCode> {
    // Check the app before credentials, so a typo doesn't cost a Keychain
    // lookup or a password prompt.
    let app = AppInfo::read(&args.app)?;
    let options = PackageOptions {
        identifier: args.identifier,
        identifier_prefix: config.package.identifier_prefix.clone(),
        version: args.pkg_version,
        install_location: args
            .install_location
            .or_else(|| config.package.install_location.clone())
            .unwrap_or_else(|| PathBuf::from("/Applications")),
    };
    let (identifier, version) = app_pkg::plan(&app, &options)?;

    let build = app.build.as_deref().unwrap_or("unknown");
    let archs = if app.architectures.is_empty() {
        String::new()
    } else {
        format!("; {}", app.architectures.join(", "))
    };
    eprintln!(
        "Packaging {} {} (build {build}{archs})",
        app.name,
        app.version.as_deref().unwrap_or("(no version)")
    );
    eprintln!(
        "  Installs to: {}",
        options.install_location.join(&app.name).display()
    );
    eprintln!("  Package ID:  {identifier}");
    eprintln!("  Version:     {version}");

    let identity = creds::load_identity(&args.signing.identity, config)?;
    let sign = sign_options(&args.signing, args.force, false, config);
    announce_keychain(&identity);
    if sign.timestamp {
        eprintln!("The signature gets a secure timestamp (needs an internet connection).");
    }

    let packaged = app_pkg::package_app(
        &args.app,
        args.output.as_deref(),
        &identity,
        &sign,
        &options,
        &mut |line| eprintln!("{line}"),
    )?;

    for warning in &packaged.sign.warnings {
        eprintln!("warning: {warning}");
    }
    println!(
        "Built and signed {} using {}",
        packaged.sign.output.display(),
        packaged.sign.backend
    );
    eprintln!(
        "It installs {} and upgrades an existing copy there. Installer refuses to replace a newer version.",
        packaged.install_path.display()
    );
    eprintln!(
        "Keep the package ID ({}) the same for future versions of this app so MDMs treat them as upgrades.",
        packaged.identifier
    );
    eprintln!(
        "Next: `mdmsign notarize {}` (recommended), then `mdmsign verify` before uploading. Quit the app on target Macs before deploying.",
        packaged.sign.output.display()
    );
    Ok(ExitCode::SUCCESS)
}
