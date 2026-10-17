//! Verifying configuration profiles.
//!
//! Signature checks use `cryptographic-message-syntax` and work on any
//! platform. On macOS, [`VerifyOptions::system_checks`] also asks
//! `security verify-cert` whether the system trusts the signing certificate.

use std::path::Path;

use apple_codesign::{AppleCertificate, KnownCertificate};
use chrono::Utc;
use cryptographic_message_syntax::SignedData;
use x509_certificate::CapturedX509Certificate;

use crate::{
    ArtifactKind, CertKind, Result,
    error::io_error,
    identity::Suitability,
    sign::profile::{
        ProfileError, looks_signed, parse_signed_data, reparse_der, signed_content,
        signer_certificate, validate_content,
    },
    verify::{Check, CheckId, Report, SignerInfo, VerifyOptions},
};

/// Verifies a `.mobileconfig`: signed or not, CMS signature, certificate,
/// chain, and that the payload is a well-formed configuration profile.
pub fn verify(path: &Path, options: &VerifyOptions) -> Result<Report> {
    let mut report = Report::new(path, ArtifactKind::ConfigurationProfile);
    let data = std::fs::read(path).map_err(io_error("read", path))?;
    let file = path.display().to_string();

    // Format: unwrap the signature, if any.
    let signed = if looks_signed(&data) {
        match parse_signed_data(&data).and_then(|s| signed_content(&s).map(|c| (s, c))) {
            Ok(parsed) => Some(parsed),
            Err(err) => {
                report.push(error_check(CheckId::Format, &err));
                skip_rest(&mut report, "the signature data can't be read");
                return Ok(report);
            }
        }
    } else {
        None
    };
    let content: &[u8] = match &signed {
        Some((_, content)) => content,
        None => &data,
    };

    // ProfileContent: what's inside is a configuration profile.
    match validate_content(content) {
        Ok(summary) => {
            report.push(Check::pass(
                CheckId::Format,
                format!(
                    "{} {} property list",
                    if signed.is_some() {
                        "Signed (CMS)"
                    } else {
                        "Unsigned"
                    },
                    if summary.binary { "binary" } else { "XML" },
                ),
            ));
            let name = summary
                .display_name
                .as_deref()
                .map(|n| format!("\"{n}\" "))
                .unwrap_or_default();
            let payloads = match summary.payload_count {
                1 => "1 payload".to_string(),
                n => format!("{n} payloads"),
            };
            report.push(
                Check::pass(
                    CheckId::ProfileContent,
                    format!(
                        "Configuration profile {name}({}) with {payloads}",
                        summary.identifier
                    ),
                )
                .with_detail(format!("PayloadUUID: {}", summary.uuid)),
            );
        }
        Err(err @ (ProfileError::InvalidPlist { .. } | ProfileError::NotADictionary { .. })) => {
            report.push(error_check(CheckId::Format, &err));
            report.push(Check::skip(
                CheckId::ProfileContent,
                "Profile content not checked: it isn't a readable property list",
            ));
        }
        Err(err) => {
            report.push(Check::pass(CheckId::Format, "Readable property list"));
            report.push(error_check(CheckId::ProfileContent, &err));
        }
    }

    let Some((signed, _)) = signed else {
        report.push(Check::warn(
            CheckId::Signed,
            "Not signed",
            format!(
                "Most MDMs accept unsigned profiles and sign them when delivering them. To sign it yourself, run `mdmsign sign {file}`."
            ),
        ));
        skip_rest(&mut report, "the profile isn't signed");
        return Ok(report);
    };

    let Some(first) = signed.signers().next() else {
        report.push(Check::fail(
            CheckId::Signed,
            "The signature has no signers",
            format!("Sign the original profile again with `mdmsign sign --resign {file}`."),
        ));
        skip_rest(&mut report, "the signature has no signers");
        return Ok(report);
    };
    let leaf = signer_certificate(&signed, first);
    let signed_by = leaf
        .as_ref()
        .and_then(|c| c.subject_common_name())
        .unwrap_or_else(|| "an unknown certificate".into());
    report.push(Check::pass(
        CheckId::Signed,
        format!("Signed by {signed_by}"),
    ));

    report.push(signature_check(&signed, &file));

    let Some(leaf) = leaf else {
        skip_certificate_checks(&mut report, "the signing certificate isn't in the file");
        return Ok(report);
    };
    report.signer = Some(SignerInfo::from_certificate(&leaf));
    report.push(certificate_type_check(&leaf));
    report.push(certificate_validity_check(&leaf, &file));
    // The other certificates in the signature: candidates for the chain.
    let others: Vec<CapturedX509Certificate> = signed
        .certificates()
        .filter(|c| c.constructed_data() != leaf.constructed_data())
        .map(reparse_der)
        .collect();
    report.push(chain_check(&leaf, &others));

    if options.system_checks && cfg!(target_os = "macos") {
        report.push(system_check(&leaf, &others, options.offline));
    }

    Ok(report)
}

fn error_check(id: CheckId, err: &ProfileError) -> Check {
    let summary = capitalize(&err.to_string());
    Check::fail(
        id,
        summary,
        err.hint()
            .unwrap_or_else(|| "Check the file and try again.".into()),
    )
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Adds Skip checks for everything that hasn't been reported yet.
fn skip_rest(report: &mut Report, reason: &str) {
    for (id, what) in [
        (CheckId::ProfileContent, "Profile content"),
        (CheckId::Signed, "Signer"),
        (CheckId::SignatureValid, "Signature"),
    ] {
        if report.check(id).is_none() {
            report.push(Check::skip(id, format!("{what} not checked: {reason}")));
        }
    }
    skip_certificate_checks(report, reason);
}

fn skip_certificate_checks(report: &mut Report, reason: &str) {
    for (id, what) in [
        (CheckId::CertificateType, "Certificate type"),
        (CheckId::CertificateValidity, "Certificate dates"),
        (CheckId::CertificateChain, "Certificate chain"),
    ] {
        report.push(Check::skip(id, format!("{what} not checked: {reason}")));
    }
}

/// Verifies every signer's signature and message digest.
fn signature_check(signed: &SignedData, file: &str) -> Check {
    let resign = format!(
        "The profile was changed after it was signed, or the signature is damaged. Sign the original profile again with `mdmsign sign --resign {file}`."
    );
    for (index, signer) in signed.signers().enumerate() {
        let label = if signed.signers().count() > 1 {
            format!("Signer {}: ", index + 1)
        } else {
            String::new()
        };
        if signer_certificate(signed, signer).is_none() {
            return Check::fail(
                CheckId::SignatureValid,
                format!("{label}The signing certificate isn't included in the signature"),
                format!(
                    "Macs can't check a signature without its certificate. Sign the profile again with `mdmsign sign --resign {file}`."
                ),
            );
        }
        if let Err(e) = signer.verify_signature_with_signed_data(signed) {
            return Check::fail(
                CheckId::SignatureValid,
                format!("{label}The signature is invalid"),
                resign,
            )
            .with_detail(e.to_string());
        }
        match signer.verify_message_digest_with_signed_data(signed) {
            // Without signed attributes the signature covers the content
            // directly, so verifying it above already checked the content.
            Ok(()) | Err(cryptographic_message_syntax::CmsError::NoSignedAttributes) => {}
            Err(e) => {
                return Check::fail(
                    CheckId::SignatureValid,
                    format!("{label}The profile doesn't match its signature"),
                    resign,
                )
                .with_detail(e.to_string());
            }
        }
    }
    Check::pass(CheckId::SignatureValid, "Signature is valid")
}

fn certificate_type_check(leaf: &CapturedX509Certificate) -> Check {
    let kind = CertKind::classify(leaf);
    match kind.suitability(ArtifactKind::ConfigurationProfile) {
        Suitability::Suitable => Check::pass(
            CheckId::CertificateType,
            format!("Signed with a {kind} certificate"),
        ),
        Suitability::Discouraged { reason } => Check::warn(
            CheckId::CertificateType,
            format!("Signed with a {kind}: {reason}"),
            "Sign with an Apple-issued certificate such as Developer ID Application (`mdmsign certs` lists yours), or make sure your MDM deploys the issuing CA's root certificate to your Macs.",
        ),
        Suitability::Unsuitable { reason, fix } => Check::fail(
            CheckId::CertificateType,
            format!("Signed with a {kind}: {reason}"),
            fix,
        ),
    }
}

fn certificate_validity_check(leaf: &CapturedX509Certificate, file: &str) -> Check {
    let now = Utc::now();
    let not_before = leaf.validity_not_before();
    let not_after = leaf.validity_not_after();
    let fix = format!(
        "Profiles aren't timestamped, so Macs check the certificate's dates when the profile is installed. Sign it again with a current certificate: `mdmsign sign --resign {file}`."
    );
    if now > not_after {
        Check::fail(
            CheckId::CertificateValidity,
            format!(
                "The signing certificate expired on {}",
                not_after.format("%Y-%m-%d")
            ),
            fix,
        )
    } else if now < not_before {
        Check::fail(
            CheckId::CertificateValidity,
            format!(
                "The signing certificate isn't valid until {}",
                not_before.format("%Y-%m-%d")
            ),
            format!("Check this computer's clock. {fix}"),
        )
    } else {
        Check::pass(
            CheckId::CertificateValidity,
            format!(
                "Certificate is valid until {}",
                not_after.format("%Y-%m-%d")
            ),
        )
    }
}

/// Whether `leaf` chains to an Apple root, using the certificates embedded
/// in the signature plus apple-codesign's known Apple CA certificates.
fn chains_to_apple_root(
    leaf: &CapturedX509Certificate,
    others: &[CapturedX509Certificate],
) -> bool {
    if leaf.chains_to_apple_root_ca() {
        return true;
    }
    let candidates = others.iter().chain(KnownCertificate::all().iter().copied());
    leaf.resolve_signing_chain(candidates)
        .into_iter()
        .any(AppleCertificate::is_apple_root_ca)
}

fn chain_check(leaf: &CapturedX509Certificate, others: &[CapturedX509Certificate]) -> Check {
    if chains_to_apple_root(leaf, others) {
        Check::pass(
            CheckId::CertificateChain,
            "Certificate chains to an Apple root CA",
        )
    } else {
        let detail = match leaf.issuer_common_name() {
            Some(issuer) if leaf.subject_is_issuer() => {
                format!("The certificate is self-signed (issuer: {issuer}).")
            }
            Some(issuer) => format!("Issued by: {issuer}"),
            None => "The issuer has no common name.".into(),
        };
        Check::warn(
            CheckId::CertificateChain,
            "Certificate doesn't chain to an Apple root CA, so Macs will show the profile as Not Verified",
            "Sign with an Apple-issued certificate such as Developer ID Application, or deploy your CA's root certificate to your Macs first. Many MDMs re-sign profiles on delivery, in which case this doesn't matter.",
        )
        .with_detail(detail)
    }
}

/// Asks macOS whether it trusts the signing certificate, the way it will
/// when the profile is installed.
///
/// This deliberately uses `security verify-cert` on the certificates from
/// the signature rather than `security cms -D`: decoding with `security cms`
/// imports every certificate embedded in the profile into the user's default
/// keychain, which a read-only check must never do.
fn system_check(
    leaf: &CapturedX509Certificate,
    others: &[CapturedX509Certificate],
    offline: bool,
) -> Check {
    let dir = match tempfile::Builder::new().prefix("mdmsign-verify-").tempdir() {
        Ok(dir) => dir,
        Err(e) => {
            return Check::skip(
                CheckId::Gatekeeper,
                format!("macOS trust check not run: couldn't create a temporary directory: {e}"),
            );
        }
    };
    // Leaf first, then the other embedded certificates as chain candidates.
    let mut args: Vec<std::ffi::OsString> = vec!["verify-cert".into()];
    for (index, cert) in std::iter::once(leaf).chain(others).enumerate() {
        let path = dir.path().join(format!("cert{index}.der"));
        if let Err(e) = std::fs::write(&path, cert.constructed_data()) {
            return Check::skip(
                CheckId::Gatekeeper,
                format!("macOS trust check not run: couldn't write a certificate: {e}"),
            );
        }
        args.push("-c".into());
        args.push(path.into());
    }
    args.extend(["-p".into(), "basic".into()]);
    if offline {
        // Don't fetch missing intermediate certificates from the network.
        args.push("-L".into());
    }
    let output = match crate::tool::run_unchecked("/usr/bin/security", &args) {
        Ok(output) => output,
        Err(e) => {
            return Check::skip(
                CheckId::Gatekeeper,
                format!("macOS trust check not run: {e}"),
            );
        }
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    trust_check_from_output(output.status.success(), &text)
}

/// Turns `security verify-cert` output into a check. Never fails: an
/// untrusted profile still installs (as "Not Verified"), test and
/// enterprise certificates are legitimate, and expiry is already a
/// [`CheckId::CertificateValidity`] failure.
fn trust_check_from_output(success: bool, output: &str) -> Check {
    if success {
        return Check::pass(CheckId::Gatekeeper, "macOS trusts the signing certificate");
    }
    let result = output
        .lines()
        .find_map(|line| line.trim().strip_prefix("Cert Verify Result:"))
        .map(|r| r.trim().to_string());
    let (summary, fix) = match result.as_deref() {
        Some("CSSMERR_TP_CERT_EXPIRED") => (
            "macOS rejects the signing certificate because it has expired",
            "Sign the profile again with a current certificate using `mdmsign sign --resign <file>`.",
        ),
        Some("CSSMERR_TP_CERT_REVOKED") => (
            "macOS reports the signing certificate has been revoked",
            "Create a new certificate at https://developer.apple.com/account/resources/certificates and sign the profile again with `mdmsign sign --resign <file>`.",
        ),
        _ => (
            "macOS doesn't trust the signing certificate, so it will show the profile as Not Verified",
            "Sign with an Apple-issued certificate such as Developer ID Application, or deploy the issuing CA's root certificate to your Macs.",
        ),
    };
    let detail = match result {
        Some(result) => format!("security verify-cert: {result}"),
        None => format!("security verify-cert: {}", output.trim()),
    };
    Check::warn(CheckId::Gatekeeper, summary, fix).with_detail(detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::Status;

    #[test]
    fn interprets_verify_cert_output() {
        let check = trust_check_from_output(true, "...certificate verification successful.\n");
        assert_eq!(check.status, Status::Pass);

        let check = trust_check_from_output(false, "Cert Verify Result: CSSMERR_TP_NOT_TRUSTED\n");
        assert_eq!(check.status, Status::Warn);
        assert!(check.summary.contains("Not Verified"));
        assert_eq!(
            check.detail.as_deref(),
            Some("security verify-cert: CSSMERR_TP_NOT_TRUSTED")
        );

        let check = trust_check_from_output(false, "Cert Verify Result: CSSMERR_TP_CERT_EXPIRED");
        assert_eq!(check.status, Status::Warn);
        assert!(check.summary.contains("expired"));
    }

    #[test]
    fn capitalizes_messages() {
        assert_eq!(capitalize("the profile"), "The profile");
        assert_eq!(capitalize(""), "");
    }
}
