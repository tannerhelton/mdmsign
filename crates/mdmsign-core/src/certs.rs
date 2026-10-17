//! Listing signing identities and flagging the wrong certificate types.
//!
//! [`list`] gathers identities from the macOS Keychain and any `.p12` files
//! the admin passed, and turns each into a [`CertEntry`]: what it can sign
//! right now and, in plain language, what's wrong with it.

use chrono::{DateTime, Utc};
use serde::Serialize;
use x509_certificate::CapturedX509Certificate;

use crate::{
    ArtifactKind, CertKind, Result, SigningIdentity,
    identity::Suitability,
    keychain::{self, KeychainIdentity},
};

/// [`CertEntry::source`] for identities found in the macOS Keychain.
pub const KEYCHAIN_SOURCE: &str = "keychain";

/// Certificates expiring within this many days get a warning note.
pub const EXPIRY_WARNING_DAYS: i64 = 30;

/// Where to get a Developer ID Installer certificate, for people who don't
/// have one yet.
pub const GET_INSTALLER_CERT_STEPS: &str = "\
To sign .pkg installers you need a Developer ID Installer certificate:
  1. Sign in at https://developer.apple.com/account/resources/certificates as the
     team's Account Holder (only the Account Holder can create Developer ID certificates).
  2. Click +, choose \"Developer ID Installer\", and upload a certificate signing request
     (Keychain Access > Certificate Assistant > Request a Certificate From a
     Certificate Authority, saved to disk).
  3. Download the certificate and double-click it to install it next to its private key.
  4. Run `mdmsign certs` again; it should show .pkg as ready.
To use it on another Mac or in CI, export it with its private key as a .p12
from Keychain Access and pass it with --p12.";

/// One identity, with what it can and can't sign.
#[derive(Clone, Debug, Serialize)]
pub struct CertEntry {
    /// `keychain` or the `.p12` it came from.
    pub source: String,
    pub name: String,
    pub sha1: String,
    pub kind: CertKind,
    pub team_id: Option<String>,
    pub not_after: Option<DateTime<Utc>>,
    /// True if it can sign at least one supported file type now.
    pub usable: bool,
    /// File types this identity can sign.
    pub can_sign: Vec<ArtifactKind>,
    /// Problems and advice, e.g. "can't sign .pkg; you need Developer ID Installer".
    pub notes: Vec<String>,
}

impl CertEntry {
    /// Whether `mdmsign certs` hides this entry unless `--all` is given:
    /// non-Apple Keychain identities such as MDM device-trust or Wi-Fi
    /// certificates, which are rarely what an admin wants to sign with.
    pub fn hidden_unless_all(&self) -> bool {
        self.kind == CertKind::Other && self.source == KEYCHAIN_SOURCE
    }

    /// Whether this identity can sign `kind` without caveats.
    fn fully_suitable_for(&self, kind: ArtifactKind) -> bool {
        self.can_sign.contains(&kind) && self.kind.suitability(kind) == Suitability::Suitable
    }
}

/// Lists Keychain identities (on macOS) plus `extra` identities such as a
/// `.p12` given on the command line.
///
/// Off macOS, `include_keychain` is ignored: there's no Keychain to read.
/// Every identity is returned, including non-Apple ones; use
/// [`CertEntry::hidden_unless_all`] to decide what to show.
pub fn list(include_keychain: bool, extra: &[SigningIdentity]) -> Result<Vec<CertEntry>> {
    let now = Utc::now();
    let mut entries = Vec::new();
    if include_keychain && cfg!(target_os = "macos") {
        let identities = keychain::list_identities()?;
        entries.extend(entries_from_keychain(
            &identities,
            |id| keychain::certificate(&id.sha1, &id.name).ok(),
            now,
        ));
    }
    entries.extend(
        extra
            .iter()
            .map(|identity| entry_for_identity(identity, now)),
    );
    Ok(entries)
}

/// Builds entries for Keychain identities. `load` fetches each identity's
/// certificate; when it can't, the type is guessed from the name.
pub fn entries_from_keychain(
    identities: &[KeychainIdentity],
    mut load: impl FnMut(&KeychainIdentity) -> Option<CapturedX509Certificate>,
    now: DateTime<Utc>,
) -> Vec<CertEntry> {
    identities
        .iter()
        .map(|id| {
            let cert = load(id);
            let facts = match &cert {
                Some(cert) => Facts::from_certificate(cert),
                None => Facts {
                    kind: CertKind::from_common_name(&id.name),
                    team_id: team_id_from_name(&id.name),
                    not_before: None,
                    not_after: None,
                },
            };
            build_entry(
                KEYCHAIN_SOURCE.into(),
                id.name.clone(),
                id.sha1.clone(),
                facts,
                id.invalid_reason.as_deref(),
                now,
            )
        })
        .collect()
}

/// Builds the entry for an identity that's already loaded (e.g. a `.p12`).
pub fn entry_for_identity(identity: &SigningIdentity, now: DateTime<Utc>) -> CertEntry {
    build_entry(
        identity.source().to_string(),
        identity.common_name(),
        identity.sha1_fingerprint(),
        Facts::from_certificate(identity.certificate()),
        None,
        now,
    )
}

/// The best identity for signing `kind`: fully suitable ones before
/// discouraged ones, then the one that stays valid longest.
pub fn best_for(entries: &[CertEntry], kind: ArtifactKind) -> Option<&CertEntry> {
    entries
        .iter()
        .filter(|e| e.can_sign.contains(&kind))
        .max_by_key(|e| (e.fully_suitable_for(kind), e.not_after))
}

/// Whether any entry is a usable Developer ID Installer identity.
pub fn has_usable_installer(entries: &[CertEntry]) -> bool {
    entries
        .iter()
        .any(|e| e.kind == CertKind::DeveloperIdInstaller && e.usable)
}

/// What we know about a certificate.
struct Facts {
    kind: CertKind,
    team_id: Option<String>,
    not_before: Option<DateTime<Utc>>,
    not_after: Option<DateTime<Utc>>,
}

impl Facts {
    fn from_certificate(cert: &CapturedX509Certificate) -> Self {
        use apple_codesign::AppleCertificate;
        let name = cert.subject_common_name().unwrap_or_default();
        Self {
            kind: CertKind::classify(cert),
            team_id: cert.apple_team_id().or_else(|| team_id_from_name(&name)),
            not_before: Some(cert.validity_not_before()),
            not_after: Some(cert.validity_not_after()),
        }
    }
}

fn build_entry(
    source: String,
    name: String,
    sha1: String,
    facts: Facts,
    invalid_reason: Option<&str>,
    now: DateTime<Utc>,
) -> CertEntry {
    let mut notes = Vec::new();
    let mut valid = true;

    if let Some(reason) = invalid_reason {
        valid = false;
        notes.push(invalid_reason_note(reason));
    }
    if let Some(not_after) = facts.not_after {
        if now > not_after {
            if valid {
                notes.push(format!(
                    "Expired on {}. Create a replacement at https://developer.apple.com/account/resources/certificates.",
                    not_after.format("%Y-%m-%d")
                ));
            }
            valid = false;
        } else if valid {
            let days = (not_after - now).num_days();
            if days < EXPIRY_WARNING_DAYS {
                let when = match days {
                    0 => "today".to_string(),
                    1 => "in 1 day".to_string(),
                    n => format!("in {n} days"),
                };
                notes.push(format!(
                    "Expires {when} ({}). Create a replacement before then; files signed and timestamped before it expires keep working.",
                    not_after.format("%Y-%m-%d")
                ));
            }
        }
    }
    if let Some(not_before) = facts.not_before
        && now < not_before
    {
        if valid {
            notes.push(format!(
                "Not valid until {}. Check your Mac's clock if that looks wrong.",
                not_before.format("%Y-%m-%d")
            ));
        }
        valid = false;
    }

    // For an unusable identity the type advice is noise, except for the
    // types people most often mistake for an installer certificate.
    let commonly_mistaken = matches!(
        facts.kind,
        CertKind::DeveloperIdApplication | CertKind::MacInstallerDistribution
    );
    if (valid || commonly_mistaken)
        && let Some(note) = kind_note(facts.kind)
    {
        notes.push(note.into());
    }

    let can_sign: Vec<ArtifactKind> = if valid {
        ArtifactKind::ALL
            .iter()
            .copied()
            .filter(|&kind| !matches!(facts.kind.suitability(kind), Suitability::Unsuitable { .. }))
            .collect()
    } else {
        Vec::new()
    };

    CertEntry {
        source,
        name,
        sha1,
        kind: facts.kind,
        team_id: facts.team_id,
        not_after: facts.not_after,
        usable: !can_sign.is_empty(),
        can_sign,
        notes,
    }
}

fn invalid_reason_note(code: &str) -> String {
    let described = keychain::describe_invalid_reason(code);
    let advice = match code {
        "CSSMERR_TP_NOT_TRUSTED" => {
            "Install Apple's Developer ID intermediate certificates (Developer ID - G1 and G2) from https://www.apple.com/certificateauthority/, then run `mdmsign certs` again."
        }
        "CSSMERR_TP_CERT_NOT_VALID_YET" => "Check your Mac's date and time.",
        _ => "Create a replacement at https://developer.apple.com/account/resources/certificates.",
    };
    format!("macOS reports this identity as {described}. {advice}")
}

fn kind_note(kind: CertKind) -> Option<&'static str> {
    Some(match kind {
        CertKind::DeveloperIdInstaller => return None,
        CertKind::DeveloperIdApplication => {
            "Developer ID Application can't sign .pkg; you need Developer ID Installer. It can still sign .mobileconfig profiles."
        }
        CertKind::MacInstallerDistribution => {
            "Mac Installer Distribution is for the Mac App Store only; Macs won't trust a .pkg signed with it when an MDM installs it. Use Developer ID Installer."
        }
        CertKind::AppleDistribution => {
            "Apple Distribution can't sign .pkg; you need Developer ID Installer. It can still sign .mobileconfig profiles."
        }
        CertKind::AppleDevelopment => {
            "Apple Development can't sign .pkg; you need Developer ID Installer. It can sign .mobileconfig profiles, but a Developer ID certificate is a better choice for production."
        }
        CertKind::Other => {
            "Not an Apple certificate: it can't sign .pkg, and profiles signed with it show as \"Not Verified\" unless your Macs trust its root CA."
        }
    })
}

/// Extracts `ABCDE12345` from `Developer ID Installer: Example (ABCDE12345)`.
fn team_id_from_name(name: &str) -> Option<String> {
    let inner = name.trim_end().strip_suffix(')')?;
    let (_, id) = inner.rsplit_once('(')?;
    (id.len() == 10
        && id
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()))
    .then(|| id.to_string())
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;
    use crate::{Secret, keychain::parse_find_identity, testutil::TestIdentity};

    fn load(kind: CertKind) -> SigningIdentity {
        let test = TestIdentity::generate(kind);
        SigningIdentity::from_p12(&test.p12, &Secret::new(&test.password), "test.p12").unwrap()
    }

    #[test]
    fn team_id_parsing() {
        assert_eq!(
            team_id_from_name("Developer ID Installer: Example Corp (ABCDE12345)").as_deref(),
            Some("ABCDE12345")
        );
        assert_eq!(team_id_from_name("Device Trust (Quote) (x)"), None);
        assert_eq!(team_id_from_name("example.com"), None);
    }

    #[test]
    fn keychain_entries_fall_back_to_name() {
        let ids = parse_find_identity(
            r#"  1) 1111111111111111111111111111111111111111 "Developer ID Installer: Example Corp (ABCDE12345)"
  2) 2222222222222222222222222222222222222222 "Developer ID Application: Example Corp (ABCDE12345)" (CSSMERR_TP_CERT_EXPIRED)
  3) 3333333333333333333333333333333333333333 "Device Trust (Quote) (x)"
  4) 4444444444444444444444444444444444444444 "3rd Party Mac Developer Installer: Example Corp (ABCDE12345)"
  5) 5555555555555555555555555555555555555555 "Developer ID Installer: Example Corp (ABCDE12345)" (CSSMERR_TP_NOT_TRUSTED)
"#,
        );
        let entries = entries_from_keychain(&ids, |_| None, Utc::now());
        assert_eq!(entries.len(), 5);

        assert_eq!(entries[0].kind, CertKind::DeveloperIdInstaller);
        assert_eq!(entries[0].team_id.as_deref(), Some("ABCDE12345"));
        assert_eq!(
            entries[0].can_sign,
            [
                ArtifactKind::FlatPackage,
                ArtifactKind::ConfigurationProfile
            ]
        );
        assert!(entries[0].notes.is_empty(), "{:?}", entries[0].notes);

        assert!(!entries[1].usable);
        assert!(entries[1].can_sign.is_empty());
        assert!(
            entries[1].notes[0].contains("expired"),
            "{:?}",
            entries[1].notes
        );

        assert!(entries[2].hidden_unless_all());
        assert!(!entries[0].hidden_unless_all());

        assert_eq!(entries[3].kind, CertKind::MacInstallerDistribution);
        assert_eq!(entries[3].can_sign, [ArtifactKind::ConfigurationProfile]);
        assert!(entries[3].notes[0].contains("Mac App Store only"));

        assert!(entries[4].notes[0].contains("not trusted"));
        assert!(entries[4].notes[0].contains("apple.com/certificateauthority"));

        assert_eq!(
            best_for(&entries, ArtifactKind::FlatPackage).map(|e| e.sha1.as_str()),
            Some("1".repeat(40).as_str())
        );
        assert!(has_usable_installer(&entries));
    }

    #[test]
    fn keychain_entries_use_loaded_certificate() {
        let test = TestIdentity::generate(CertKind::DeveloperIdApplication);
        // The name says Installer, but the certificate itself wins.
        let ids = parse_find_identity(
            r#"  1) 1111111111111111111111111111111111111111 "Developer ID Installer: Mislabelled (ABCDE12345)""#,
        );
        let entries = entries_from_keychain(&ids, |_| Some(test.certificate.clone()), Utc::now());
        assert_eq!(entries[0].kind, CertKind::DeveloperIdApplication);
        assert_eq!(
            entries[0].team_id.as_deref(),
            Some(crate::testutil::TEAM_ID)
        );
        assert!(entries[0].not_after.is_some());
    }

    #[test]
    fn application_cert_explains_installer_need() {
        let identity = load(CertKind::DeveloperIdApplication);
        let entry = entry_for_identity(&identity, Utc::now());
        assert_eq!(entry.source, "test.p12");
        assert_eq!(entry.kind, CertKind::DeveloperIdApplication);
        assert_eq!(entry.can_sign, [ArtifactKind::ConfigurationProfile]);
        assert!(entry.usable);
        assert!(!entry.hidden_unless_all());
        assert!(
            entry
                .notes
                .iter()
                .any(|n| n.contains("can't sign .pkg; you need Developer ID Installer")),
            "{:?}",
            entry.notes
        );
        // Test certificates are valid for two days.
        assert!(
            entry
                .notes
                .iter()
                .any(|n| n.starts_with("Expires in 1 day")),
            "{:?}",
            entry.notes
        );
        assert!(!has_usable_installer(std::slice::from_ref(&entry)));
        assert!(best_for(std::slice::from_ref(&entry), ArtifactKind::FlatPackage).is_none());
    }

    #[test]
    fn expired_and_future_certificates_are_unusable() {
        let identity = load(CertKind::DeveloperIdInstaller);
        let later = identity.not_after() + Duration::days(1);
        let entry = entry_for_identity(&identity, later);
        assert!(!entry.usable);
        assert!(
            entry.notes[0].starts_with("Expired on"),
            "{:?}",
            entry.notes
        );

        let earlier = identity.certificate().validity_not_before() - Duration::days(1);
        let entry = entry_for_identity(&identity, earlier);
        assert!(!entry.usable);
        assert!(entry.notes.iter().any(|n| n.starts_with("Not valid until")));
    }

    #[test]
    fn installer_cert_is_ready_for_everything() {
        let identity = load(CertKind::DeveloperIdInstaller);
        let entry = entry_for_identity(&identity, Utc::now());
        assert_eq!(
            entry.can_sign,
            [
                ArtifactKind::FlatPackage,
                ArtifactKind::ConfigurationProfile
            ]
        );
        let app = entry_for_identity(&load(CertKind::DeveloperIdApplication), Utc::now());
        let entries = [app, entry];
        assert_eq!(
            best_for(&entries, ArtifactKind::FlatPackage).unwrap().kind,
            CertKind::DeveloperIdInstaller
        );
        assert!(has_usable_installer(&entries));
    }

    #[test]
    fn list_without_keychain_returns_extras() {
        let identity = load(CertKind::DeveloperIdInstaller);
        let entries = list(false, std::slice::from_ref(&identity)).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sha1, identity.sha1_fingerprint());
    }
}
