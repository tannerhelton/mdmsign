//! Command-line interface definition.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

const AFTER_HELP: &str = "\
Credentials are read from flags, then environment variables, then the config file
(~/.config/mdmsign/config.toml or MDMSIGN_CONFIG):
  MDMSIGN_IDENTITY        Keychain identity name or SHA-1 (macOS)
  MDMSIGN_P12_PATH        Path to a .p12 signing identity
  MDMSIGN_P12_BASE64      Base64-encoded .p12 (for CI secrets)
  MDMSIGN_P12_PASSWORD    Password for the .p12
  MDMSIGN_ASC_KEY_PATH    App Store Connect API key (.p8) for notarization
  MDMSIGN_ASC_KEY         App Store Connect API key contents (for CI secrets)
  MDMSIGN_ASC_KEY_ID      App Store Connect API key ID
  MDMSIGN_ASC_ISSUER_ID   App Store Connect issuer ID

Exit status: 0 success, 1 failure (or not MDM-ready), 2 usage or credential error.";

/// Sign, notarize and verify macOS packages and configuration profiles so
/// they're ready to upload to an MDM.
#[derive(Debug, Parser)]
#[command(name = "mdmsign", version, after_help = AFTER_HELP)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    /// Config file to use instead of the default location.
    #[arg(long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Sign a .pkg installer or .mobileconfig profile.
    Sign(SignArgs),
    /// Wrap an installed app in a signed .pkg, ready for an MDM.
    #[command(visible_alias = "package")]
    Pkg(PkgArgs),
    /// Notarize a signed .pkg with Apple, then staple the ticket.
    Notarize(NotarizeArgs),
    /// Staple an existing notarization ticket to a .pkg.
    Staple(StapleArgs),
    /// Check a file's signature and whether it's ready to upload to an MDM.
    Verify(VerifyArgs),
    /// List signing identities and what each can sign.
    Certs(CertsArgs),
}

#[derive(Debug, Args)]
pub struct IdentityFlags {
    /// Keychain identity: its name, a unique part of it, or its SHA-1 (macOS).
    #[arg(short, long, value_name = "NAME|SHA1", conflicts_with = "p12")]
    pub identity: Option<String>,

    /// .p12 file with the certificate and private key. The password comes
    /// from MDMSIGN_P12_PASSWORD or a prompt.
    #[arg(long, value_name = "FILE")]
    pub p12: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum BackendArg {
    /// Apple's tools for Keychain identities, native for .p12 files.
    Auto,
    /// Sign in-process (needs --p12).
    Native,
    /// productsign / security cms (macOS Keychain identities).
    Apple,
}

#[derive(Debug, Args)]
pub struct SignArgs {
    /// The .pkg or .mobileconfig to sign.
    pub file: PathBuf,

    /// Where to write the signed file [default: <name>-signed.<ext>].
    #[arg(short, long, value_name = "PATH", conflicts_with = "in_place")]
    pub output: Option<PathBuf>,

    /// Replace the input file with the signed one.
    #[arg(long)]
    pub in_place: bool,

    /// Overwrite the output file if it exists.
    #[arg(short, long)]
    pub force: bool,

    /// Replace an existing signature.
    #[arg(long)]
    pub resign: bool,

    #[command(flatten)]
    pub signing: SigningFlags,
}

/// Identity and signing options shared by `sign` and `pkg`.
#[derive(Debug, Args)]
pub struct SigningFlags {
    #[command(flatten)]
    pub identity: IdentityFlags,

    /// Signing implementation.
    #[arg(long, value_enum, value_name = "BACKEND")]
    pub backend: Option<BackendArg>,

    /// Don't add a secure timestamp. Notarization requires one.
    #[arg(long, conflicts_with = "timestamp_url")]
    pub no_timestamp: bool,

    /// Timestamp server [default: Apple's].
    #[arg(long, value_name = "URL")]
    pub timestamp_url: Option<String>,
}

#[derive(Debug, Args)]
pub struct PkgArgs {
    /// The app to package, e.g. "/Applications/Example.app".
    pub app: PathBuf,

    /// Where to write the signed package [default: <Name>-<version>-signed.pkg].
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Overwrite the output file if it exists.
    #[arg(short, long)]
    pub force: bool,

    /// Package identifier (the install receipt ID). Keep it the same for
    /// every version of the app [default: <bundle-id>.pkg, or
    /// identifier_prefix + bundle ID from the config file].
    #[arg(long, value_name = "ID")]
    pub identifier: Option<String>,

    /// Installer version [default: the app's CFBundleShortVersionString].
    #[arg(long = "version", value_name = "VERSION")]
    pub pkg_version: Option<String>,

    /// Folder the app installs into [default: /Applications].
    #[arg(long, value_name = "DIR")]
    pub install_location: Option<PathBuf>,

    #[command(flatten)]
    pub signing: SigningFlags,
}

#[derive(Debug, Args)]
pub struct AscFlags {
    /// App Store Connect API key file (AuthKey_XXXXXXXXXX.p8).
    #[arg(long, value_name = "FILE")]
    pub key: Option<PathBuf>,

    /// API key ID [default: taken from the AuthKey_<ID>.p8 file name].
    #[arg(long, value_name = "ID")]
    pub key_id: Option<String>,

    /// Issuer ID, shown in App Store Connect above the API key list.
    #[arg(long, value_name = "UUID")]
    pub issuer: Option<String>,
}

#[derive(Debug, Args)]
pub struct NotarizeArgs {
    /// The signed .pkg to notarize.
    pub file: PathBuf,

    #[command(flatten)]
    pub asc: AscFlags,

    /// Upload and return without waiting for Apple's verdict. Staple later
    /// with `mdmsign staple`.
    #[arg(long)]
    pub no_wait: bool,

    /// Don't staple the ticket after notarization succeeds.
    #[arg(long)]
    pub no_staple: bool,

    /// Minutes to wait for Apple's verdict [default: 30, or `timeout_minutes`
    /// under [notarize] in the config file].
    #[arg(long, value_name = "MINUTES")]
    pub timeout: Option<u64>,

    /// Print the result as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct StapleArgs {
    /// The notarized .pkg to staple.
    pub file: PathBuf,

    /// Print the result as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// The .pkg or .mobileconfig to check.
    pub file: PathBuf,

    /// Print the report as JSON.
    #[arg(long)]
    pub json: bool,

    /// Skip checks that need the network (notarization lookup).
    #[arg(long)]
    pub offline: bool,

    /// Treat a missing notarization or staple as a failure.
    #[arg(long)]
    pub require_notarization: bool,

    /// Skip macOS's own assessment (spctl / pkgutil).
    #[arg(long)]
    pub no_system_checks: bool,
}

#[derive(Debug, Args)]
#[command(after_help = "\
Exit status: 0 if at least one identity can sign a .pkg or .mobileconfig,
1 if none can (the output explains how to get one), 2 for a credential error
such as a wrong .p12 password.")]
pub struct CertsArgs {
    /// Also inspect this .p12 file. The password comes from
    /// MDMSIGN_P12_PASSWORD or a prompt.
    #[arg(long, value_name = "FILE")]
    pub p12: Option<PathBuf>,

    /// Skip the macOS Keychain.
    #[arg(long)]
    pub no_keychain: bool,

    /// Also show non-Apple Keychain identities (e.g. MDM device or Wi-Fi
    /// certificates).
    #[arg(long)]
    pub all: bool,

    /// Print the list as JSON.
    #[arg(long)]
    pub json: bool,
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn cli_is_well_formed() {
        Cli::command().debug_assert();
    }
}
