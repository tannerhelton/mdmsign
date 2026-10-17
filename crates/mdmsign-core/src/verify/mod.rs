//! Verifying files and deciding whether they're ready for an MDM.
//!
//! Verification produces a [`Report`]: a list of [`Check`]s, each Pass,
//! Warn, Fail or Skip, with advice for anything that isn't a Pass. A file is
//! MDM-ready when no check fails. Missing notarization is a warning by
//! default because MDM installs don't go through Gatekeeper's quarantine
//! check; [`VerifyOptions::require_notarization`] makes it a failure.

pub mod pkg;
pub mod profile;

use std::path::{Path, PathBuf};

use apple_codesign::AppleCertificate;
use chrono::{DateTime, Utc};
use serde::Serialize;
use x509_certificate::CapturedX509Certificate;

use crate::{
    ArtifactKind, CertKind, Result,
    identity::{sha1_fingerprint, sha256_fingerprint},
};

/// Options for verification.
#[derive(Clone, Debug)]
pub struct VerifyOptions {
    /// Skip checks that need the network (online notarization ticket lookup).
    pub offline: bool,
    /// Treat missing notarization or staple as a failure.
    pub require_notarization: bool,
    /// On macOS, also ask the system (`spctl`, `pkgutil`) for its verdict.
    pub system_checks: bool,
}

// Not derivable on macOS, where system checks default to on.
#[allow(clippy::derivable_impls)]
impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            offline: false,
            require_notarization: false,
            system_checks: cfg!(target_os = "macos"),
        }
    }
}

impl VerifyOptions {
    /// The quick, offline check run right after signing.
    pub fn post_sign() -> Self {
        Self {
            offline: true,
            require_notarization: false,
            system_checks: false,
        }
    }
}

/// Outcome of one check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    Pass,
    Warn,
    Fail,
    /// Not applicable or not run (e.g. offline).
    Skip,
}

/// What a check looked at. Stable identifiers for `--json` consumers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum CheckId {
    /// The file parses as the expected type.
    Format,
    /// The file carries a signature.
    Signed,
    /// The signature matches the content.
    SignatureValid,
    /// The signing certificate is the right type for this file.
    CertificateType,
    /// The signing certificate is within its validity dates.
    CertificateValidity,
    /// The signing certificate chains to a trusted Apple root.
    CertificateChain,
    /// The signature has a secure timestamp.
    Timestamp,
    /// Apple has notarized the file.
    Notarization,
    /// The notarization ticket is stapled to the file.
    Staple,
    /// macOS's own assessment (`spctl`).
    Gatekeeper,
    /// The profile payload is well formed.
    ProfileContent,
}

/// One check's result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Check {
    pub id: CheckId,
    pub status: Status,
    /// One line, e.g. "Signed by Developer ID Installer: Example (ABCDE12345)".
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// What to do about a Warn or Fail.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<String>,
}

impl Check {
    fn new(id: CheckId, status: Status, summary: impl Into<String>) -> Self {
        Self {
            id,
            status,
            summary: summary.into(),
            detail: None,
            fix: None,
        }
    }

    pub fn pass(id: CheckId, summary: impl Into<String>) -> Self {
        Self::new(id, Status::Pass, summary)
    }

    pub fn warn(id: CheckId, summary: impl Into<String>, fix: impl Into<String>) -> Self {
        Self::new(id, Status::Warn, summary).with_fix(fix)
    }

    pub fn fail(id: CheckId, summary: impl Into<String>, fix: impl Into<String>) -> Self {
        Self::new(id, Status::Fail, summary).with_fix(fix)
    }

    pub fn skip(id: CheckId, summary: impl Into<String>) -> Self {
        Self::new(id, Status::Skip, summary)
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_fix(mut self, fix: impl Into<String>) -> Self {
        self.fix = Some(fix.into());
        self
    }
}

/// Facts about the signing certificate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SignerInfo {
    pub common_name: String,
    pub team_id: Option<String>,
    pub cert_kind: CertKind,
    pub issuer: Option<String>,
    pub sha1: String,
    pub sha256: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

impl SignerInfo {
    pub fn from_certificate(cert: &CapturedX509Certificate) -> Self {
        Self {
            common_name: cert.subject_common_name().unwrap_or_default(),
            team_id: cert.apple_team_id(),
            cert_kind: CertKind::classify(cert),
            issuer: cert.issuer_name().user_friendly_str().ok(),
            sha1: sha1_fingerprint(cert),
            sha256: sha256_fingerprint(cert),
            not_before: cert.validity_not_before(),
            not_after: cert.validity_not_after(),
        }
    }
}

/// The result of verifying one file.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub path: PathBuf,
    pub kind: ArtifactKind,
    pub mdm_ready: bool,
    pub signer: Option<SignerInfo>,
    pub checks: Vec<Check>,
}

impl Report {
    pub fn new(path: &Path, kind: ArtifactKind) -> Self {
        Self {
            path: path.to_path_buf(),
            kind,
            mdm_ready: false,
            signer: None,
            checks: Vec::new(),
        }
    }

    pub fn push(&mut self, check: Check) {
        self.checks.push(check);
    }

    pub fn check(&self, id: CheckId) -> Option<&Check> {
        self.checks.iter().find(|c| c.id == id)
    }

    pub fn count(&self, status: Status) -> usize {
        self.checks.iter().filter(|c| c.status == status).count()
    }

    /// Applies policy options and computes [`Report::mdm_ready`].
    pub fn finalize(mut self, options: &VerifyOptions) -> Self {
        if options.require_notarization {
            for check in &mut self.checks {
                if matches!(check.id, CheckId::Notarization | CheckId::Staple)
                    && check.status == Status::Warn
                {
                    check.status = Status::Fail;
                }
            }
        }
        self.mdm_ready = self.count(Status::Fail) == 0;
        self
    }
}

/// Verifies `path`, dispatching on its detected type.
pub fn verify_file(path: &Path, options: &VerifyOptions) -> Result<Report> {
    let kind = ArtifactKind::detect(path)?;
    let report = match kind {
        ArtifactKind::FlatPackage => pkg::verify(path, options)?,
        ArtifactKind::ConfigurationProfile => profile::verify(path, options)?,
    };
    Ok(report.finalize(options))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notarization_warning_becomes_failure_when_required() {
        let mut report = Report::new(Path::new("a.pkg"), ArtifactKind::FlatPackage);
        report.push(Check::pass(CheckId::SignatureValid, "ok"));
        report.push(Check::warn(
            CheckId::Notarization,
            "not notarized",
            "run mdmsign notarize",
        ));
        let lenient = report.clone().finalize(&VerifyOptions::default());
        assert!(lenient.mdm_ready);
        let strict = report.finalize(&VerifyOptions {
            require_notarization: true,
            ..VerifyOptions::default()
        });
        assert!(!strict.mdm_ready);
        assert_eq!(
            strict.check(CheckId::Notarization).unwrap().status,
            Status::Fail
        );
    }

    #[test]
    fn json_shape_is_stable() {
        let mut report = Report::new(
            Path::new("a.mobileconfig"),
            ArtifactKind::ConfigurationProfile,
        );
        report.push(Check::fail(
            CheckId::Signed,
            "not signed",
            "run mdmsign sign",
        ));
        let json = serde_json::to_value(report.finalize(&VerifyOptions::default())).unwrap();
        assert_eq!(json["kind"], "configuration-profile");
        assert_eq!(json["mdm_ready"], false);
        assert_eq!(json["checks"][0]["id"], "signed");
        assert_eq!(json["checks"][0]["status"], "fail");
        assert!(json["checks"][0].get("detail").is_none());
    }
}
