//! Turning flags into credentials, prompting when needed.

use std::io::IsTerminal;

use mdmsign_core::{
    Secret, SigningIdentity,
    config::Config,
    credentials::{self, IdentityArgs, IdentitySpec, ProcessEnv},
};

use crate::cli::IdentityFlags;

/// Resolves and loads the signing identity.
pub fn load_identity(
    flags: &IdentityFlags,
    config: &Config,
) -> Result<SigningIdentity, mdmsign_core::Error> {
    let args = IdentityArgs {
        identity: flags.identity.clone(),
        p12: flags.p12.clone(),
    };
    let spec = credentials::select_identity(&args, &ProcessEnv, config)?;
    if matches!(spec, IdentitySpec::Keychain(_)) {
        eprintln!("Looking up the identity in your Keychain…");
    }
    credentials::load_identity(&spec, &ProcessEnv, config, &mut prompt_password)
}

/// Prompts on the terminal; returns `None` when there isn't one (CI).
pub fn prompt_password(prompt: &str) -> Option<Secret> {
    if !std::io::stdin().is_terminal() {
        return None;
    }
    rpassword::prompt_password(prompt).ok().map(Secret::new)
}
