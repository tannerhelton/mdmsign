//! `mdmsign certs`
//!
//! Exits 0 when at least one listed identity can sign something, and 1 when
//! none can, so scripts and CI can detect a machine that isn't set up yet.

use std::{cmp::Reverse, process::ExitCode};

use mdmsign_core::{
    ArtifactKind, CertKind,
    certs::{self, CertEntry},
    config::Config,
    credentials::{self, IdentitySpec, ProcessEnv},
};

use super::creds;
use crate::{cli::CertsArgs, output};

pub fn run(args: CertsArgs, config: &Config) -> anyhow::Result<ExitCode> {
    let mut extra = Vec::new();
    if let Some(path) = &args.p12 {
        extra.push(credentials::load_identity(
            &IdentitySpec::P12File(path.clone()),
            &ProcessEnv,
            config,
            &mut creds::prompt_password,
        )?);
    }
    let include_keychain = !args.no_keychain && cfg!(target_os = "macos");
    if include_keychain && !args.json {
        eprintln!("Reading identities from your Keychain…");
    }
    let all = certs::list(include_keychain, &extra)?;
    let (mut shown, hidden): (Vec<_>, Vec<_>) = all
        .into_iter()
        .partition(|e| args.all || !e.hidden_unless_all());
    // Usable identities first, most useful type first, newest first.
    shown.sort_by_key(|e| (!e.usable, kind_rank(e.kind), Reverse(e.not_after)));

    if args.json {
        output::print_json(&shown)?;
    } else {
        print!("{}", render(&shown, hidden.len(), include_keychain));
    }
    Ok(if shown.iter().any(|e| e.usable) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn kind_rank(kind: CertKind) -> u8 {
    match kind {
        CertKind::DeveloperIdInstaller => 0,
        CertKind::DeveloperIdApplication => 1,
        CertKind::MacInstallerDistribution => 2,
        CertKind::AppleDistribution => 3,
        CertKind::AppleDevelopment => 4,
        _ => 5,
    }
}

/// Renders the identity list and a "ready to sign" summary for humans.
pub fn render(entries: &[CertEntry], hidden: usize, searched_keychain: bool) -> String {
    let mut out = String::new();
    if entries.is_empty() {
        out.push_str(if searched_keychain {
            "No signing identities found in your Keychain.\n"
        } else {
            "No signing identities to show.\n"
        });
    } else {
        let plural = if entries.len() == 1 { "y" } else { "ies" };
        out.push_str(&format!("{} signing identit{plural}:\n", entries.len()));
    }
    for entry in entries {
        out.push('\n');
        out.push_str(&render_entry(entry));
    }
    if hidden > 0 {
        let (noun, verb) = if hidden == 1 {
            ("identity", "is")
        } else {
            ("identities", "are")
        };
        out.push_str(&format!(
            "\n{hidden} non-Apple Keychain {noun} {verb} hidden; pass --all to show them.\n"
        ));
    }

    out.push_str("\nReady to sign:\n");
    for &kind in ArtifactKind::ALL {
        let label = format!(".{}", kind.extension());
        match certs::best_for(entries, kind) {
            Some(best) => out.push_str(&format!(
                "  {label:<14} ✔  {}\n",
                output::clean_line(&best.name)
            )),
            None => {
                let why = match kind {
                    ArtifactKind::FlatPackage => "no usable Developer ID Installer identity",
                    ArtifactKind::ConfigurationProfile => "no usable identity",
                };
                out.push_str(&format!("  {label:<14} ✘  {why}\n"));
            }
        }
    }
    if !certs::has_usable_installer(entries) {
        out.push('\n');
        out.push_str(certs::GET_INSTALLER_CERT_STEPS);
        out.push('\n');
    }
    out
}

fn render_entry(entry: &CertEntry) -> String {
    // Names come from certificates, which anyone can create.
    let mut out = format!("  {}\n", output::clean_line(&entry.name));
    let mut field = |label: &str, value: &str| {
        out.push_str(&format!("    {label:<10} {}\n", output::clean_line(value)));
    };
    field("Type:", entry.kind.display_name());
    field("SHA-1:", &entry.sha1);
    if let Some(team) = &entry.team_id {
        field("Team ID:", team);
    }
    if let Some(not_after) = entry.not_after {
        field("Expires:", &not_after.format("%Y-%m-%d").to_string());
    }
    let source = if entry.source == certs::KEYCHAIN_SOURCE {
        "macOS Keychain"
    } else {
        &entry.source
    };
    field("Source:", source);
    let can_sign = if entry.can_sign.is_empty() {
        "nothing right now".to_string()
    } else {
        entry
            .can_sign
            .iter()
            .map(|k| format!(".{}", k.extension()))
            .collect::<Vec<_>>()
            .join(", ")
    };
    field("Can sign:", &can_sign);
    for note in &entry.notes {
        field("Note:", note);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, kind: CertKind, can_sign: Vec<ArtifactKind>) -> CertEntry {
        CertEntry {
            source: certs::KEYCHAIN_SOURCE.into(),
            name: name.into(),
            sha1: "A".repeat(40),
            kind,
            team_id: Some("ABCDE12345".into()),
            not_after: None,
            usable: !can_sign.is_empty(),
            can_sign,
            notes: Vec::new(),
        }
    }

    #[test]
    fn summary_with_installer() {
        let entries = [entry(
            "Developer ID Installer: Example (ABCDE12345)",
            CertKind::DeveloperIdInstaller,
            vec![
                ArtifactKind::FlatPackage,
                ArtifactKind::ConfigurationProfile,
            ],
        )];
        let text = render(&entries, 2, true);
        assert!(text.starts_with("1 signing identity:\n"), "{text}");
        assert!(text.contains("    Source:    macOS Keychain\n"), "{text}");
        assert!(
            text.contains("  .pkg           ✔  Developer ID Installer: Example (ABCDE12345)\n"),
            "{text}"
        );
        assert!(text.contains("2 non-Apple Keychain identities are hidden"));
        assert!(!text.contains("Account Holder"));
    }

    #[test]
    fn summary_without_installer_explains_how_to_get_one() {
        let entries = [entry(
            "Developer ID Application: Example (ABCDE12345)",
            CertKind::DeveloperIdApplication,
            vec![ArtifactKind::ConfigurationProfile],
        )];
        let text = render(&entries, 0, false);
        assert!(
            text.contains("  .pkg           ✘  no usable Developer ID Installer identity\n"),
            "{text}"
        );
        assert!(text.contains("  .mobileconfig  ✔  Developer ID Application"));
        assert!(text.contains("Account Holder"));
    }

    #[test]
    fn empty_list() {
        let text = render(&[], 0, true);
        assert!(text.starts_with("No signing identities found in your Keychain."));
        assert!(text.contains(".mobileconfig  ✘  no usable identity"));
    }
}
