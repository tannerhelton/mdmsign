//! macOS Keychain identities, via the `security` command.
//!
//! Private keys never leave the Keychain: signing with a Keychain identity
//! goes through Apple's tools (`productsign`, `security cms`), which the
//! Keychain already trusts.

use serde::Serialize;
use x509_certificate::CapturedX509Certificate;

use crate::{
    Error, SigningIdentity, credentials::CredentialError, identity::sha1_fingerprint, tool,
};

const SECURITY: &str = "/usr/bin/security";

/// An identity (certificate with a private key) found in the Keychain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KeychainIdentity {
    /// Uppercase hex SHA-1 fingerprint.
    pub sha1: String,
    /// The certificate's common name, e.g. `Developer ID Installer: Example (ABCDE12345)`.
    pub name: String,
    /// Why macOS considers it invalid (e.g. `CSSMERR_TP_CERT_EXPIRED`), if it does.
    pub invalid_reason: Option<String>,
}

/// Lists all identities in the user's Keychain search list.
pub fn list_identities() -> Result<Vec<KeychainIdentity>, Error> {
    ensure_available()?;
    let output = tool::run(SECURITY, ["find-identity", "-p", "basic"])?;
    Ok(parse_find_identity(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

/// Finds the identity matching `query` and loads its certificate.
///
/// `query` may be a 40-character SHA-1 fingerprint, the exact name, or a
/// case-insensitive part of the name that matches exactly one identity.
pub fn load_identity(query: &str) -> Result<SigningIdentity, Error> {
    let identities = list_identities()?;
    let found = find_identity(&identities, query)?;
    if let Some(reason) = &found.invalid_reason {
        return Err(CredentialError::IdentityInvalid {
            name: found.name.clone(),
            reason: describe_invalid_reason(reason),
        }
        .into());
    }
    let certificate = certificate(&found.sha1, &found.name)?;
    Ok(SigningIdentity::from_keychain(
        certificate,
        found.sha1.clone(),
    ))
}

/// Picks the identity matching `query` from `identities`.
pub fn find_identity<'a>(
    identities: &'a [KeychainIdentity],
    query: &str,
) -> Result<&'a KeychainIdentity, CredentialError> {
    let query = query.trim();
    if query.len() == 40
        && query.chars().all(|c| c.is_ascii_hexdigit())
        && let Some(found) = identities
            .iter()
            .find(|i| i.sha1.eq_ignore_ascii_case(query))
    {
        return Ok(found);
    }
    // Several Keychain entries can share a name (e.g. an expired and a
    // renewed certificate); prefer the valid ones.
    let exact: Vec<_> = identities.iter().filter(|i| i.name == query).collect();
    if let Some(found) = pick_one(&exact, query)? {
        return Ok(found);
    }
    let needle = query.to_lowercase();
    let partial: Vec<_> = identities
        .iter()
        .filter(|i| i.name.to_lowercase().contains(&needle))
        .collect();
    if let Some(found) = pick_one(&partial, query)? {
        return Ok(found);
    }
    Err(CredentialError::IdentityNotFound {
        query: query.to_string(),
        available: identities.iter().map(describe).collect(),
    })
}

fn pick_one<'a>(
    candidates: &[&'a KeychainIdentity],
    query: &str,
) -> Result<Option<&'a KeychainIdentity>, CredentialError> {
    let valid: Vec<_> = candidates
        .iter()
        .copied()
        .filter(|i| i.invalid_reason.is_none())
        .collect();
    match (valid.as_slice(), candidates) {
        ([only], _) => Ok(Some(only)),
        ([], [only]) => Ok(Some(only)),
        ([], []) => Ok(None),
        ([], many) | (many, _) => Err(CredentialError::AmbiguousIdentity {
            query: query.to_string(),
            matches: many.iter().map(|i| describe(i)).collect(),
        }),
    }
}

fn describe(identity: &KeychainIdentity) -> String {
    match &identity.invalid_reason {
        Some(reason) => format!(
            "{} ({}, {})",
            identity.name,
            identity.sha1,
            describe_invalid_reason(reason)
        ),
        None => format!("{} ({})", identity.name, identity.sha1),
    }
}

/// Turns a `CSSMERR_*` code into words.
pub fn describe_invalid_reason(code: &str) -> String {
    match code {
        "CSSMERR_TP_CERT_EXPIRED" => "expired".into(),
        "CSSMERR_TP_CERT_REVOKED" => "revoked".into(),
        "CSSMERR_TP_NOT_TRUSTED" => {
            "not trusted (the issuing certificate authority is missing or untrusted)".into()
        }
        "CSSMERR_TP_CERT_NOT_VALID_YET" => "not valid yet".into(),
        other => other.into(),
    }
}

/// Fetches the certificate with the given SHA-1 fingerprint.
pub fn certificate(sha1: &str, name: &str) -> Result<CapturedX509Certificate, Error> {
    ensure_available()?;
    let output = tool::run(SECURITY, ["find-certificate", "-a", "-Z", "-p", "-c", name])?;
    let text = String::from_utf8_lossy(&output.stdout);
    let mut current_sha1 = None;
    let mut pem = String::new();
    for line in text.lines() {
        if let Some(hash) = line.strip_prefix("SHA-1 hash: ") {
            current_sha1 = Some(hash.trim().to_string());
        } else if line.starts_with("-----BEGIN CERTIFICATE-----") {
            pem.clear();
            pem.push_str(line);
            pem.push('\n');
        } else if line.starts_with("-----END CERTIFICATE-----") {
            pem.push_str(line);
            pem.push('\n');
            if current_sha1
                .as_deref()
                .is_some_and(|h| h.eq_ignore_ascii_case(sha1))
                && let Ok(cert) = CapturedX509Certificate::from_pem(pem.as_bytes())
                && sha1_fingerprint(&cert).eq_ignore_ascii_case(sha1)
            {
                return Ok(cert);
            }
        } else if !pem.is_empty() {
            pem.push_str(line);
            pem.push('\n');
        }
    }
    Err(CredentialError::IdentityNotFound {
        query: sha1.to_string(),
        available: Vec::new(),
    }
    .into())
}

fn ensure_available() -> Result<(), Error> {
    if !cfg!(target_os = "macos") {
        return Err(CredentialError::KeychainUnsupported.into());
    }
    // Under sudo the login Keychain isn't in the search list and lookups
    // fail confusingly, so stop early.
    if let Ok(output) = tool::run("/usr/bin/id", ["-u"])
        && String::from_utf8_lossy(&output.stdout).trim() == "0"
    {
        return Err(CredentialError::RunningAsRoot.into());
    }
    Ok(())
}

/// Parses `security find-identity` output. Only the first ("Matching
/// identities") section is used; it lists every identity once.
pub fn parse_find_identity(output: &str) -> Vec<KeychainIdentity> {
    let mut identities = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("Valid identities only") {
            break;
        }
        let Some((_, rest)) = line.split_once(") ") else {
            continue;
        };
        if !line
            .split_once(')')
            .is_some_and(|(n, _)| n.chars().all(|c| c.is_ascii_digit()))
        {
            continue;
        }
        let Some((sha1, rest)) = rest.split_once(' ') else {
            continue;
        };
        if sha1.len() != 40 || !sha1.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        let Some(rest) = rest.strip_prefix('"') else {
            continue;
        };
        let Some(end) = rest.rfind('"') else { continue };
        let name = rest[..end].to_string();
        let tail = rest[end + 1..].trim();
        let invalid_reason = tail
            .strip_prefix('(')
            .and_then(|t| t.strip_suffix(')'))
            .map(str::to_string);
        identities.push(KeychainIdentity {
            sha1: sha1.to_ascii_uppercase(),
            name,
            invalid_reason,
        });
    }
    identities
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"Policy: X.509 Basic
  Matching identities
  1) 1111111111111111111111111111111111111111 "Apple Development: Jane Admin (AAAAAAAAAA)" (CSSMERR_TP_CERT_EXPIRED)
  2) 2222222222222222222222222222222222222222 "Developer ID Application: Example Corp (ABCDE12345)"
  3) 3333333333333333333333333333333333333333 "Developer ID Installer: Example Corp (ABCDE12345)"
  4) 4444444444444444444444444444444444444444 "Developer ID Installer: Example Corp (ABCDE12345)" (CSSMERR_TP_CERT_REVOKED)
  5) 5555555555555555555555555555555555555555 "Device Trust (Quote) (x)"
     5 identities found

  Valid identities only
  1) 2222222222222222222222222222222222222222 "Developer ID Application: Example Corp (ABCDE12345)"
     1 valid identities found
"#;

    #[test]
    fn parses_matching_section_only() {
        let ids = parse_find_identity(SAMPLE);
        assert_eq!(ids.len(), 5);
        assert_eq!(
            ids[0].invalid_reason.as_deref(),
            Some("CSSMERR_TP_CERT_EXPIRED")
        );
        assert_eq!(ids[1].invalid_reason, None);
        assert_eq!(ids[4].name, "Device Trust (Quote) (x)");
    }

    #[test]
    fn finds_by_name_sha1_and_substring() {
        let ids = parse_find_identity(SAMPLE);
        // Exact name shared by a valid and a revoked cert: the valid one wins.
        let found =
            find_identity(&ids, "Developer ID Installer: Example Corp (ABCDE12345)").unwrap();
        assert_eq!(found.sha1, "3".repeat(40));
        assert_eq!(
            find_identity(&ids, &"4".repeat(40)).unwrap().sha1,
            "4".repeat(40)
        );
        assert_eq!(
            find_identity(&ids, "developer id application")
                .unwrap()
                .sha1,
            "2".repeat(40)
        );
    }

    #[test]
    fn ambiguous_and_missing() {
        let ids = parse_find_identity(SAMPLE);
        assert!(matches!(
            find_identity(&ids, "Developer ID"),
            Err(CredentialError::AmbiguousIdentity { .. })
        ));
        let err = find_identity(&ids, "Nope").unwrap_err();
        let CredentialError::IdentityNotFound { available, .. } = &err else {
            panic!("{err:?}")
        };
        assert_eq!(available.len(), 5);
        assert!(available[0].contains("expired"));
    }
}
