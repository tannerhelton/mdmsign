//! Verifying flat installer packages.
//!
//! A flat package is a XAR archive. Its signature works in layers: the table
//! of contents (TOC) lists every file with a checksum of its data, a checksum
//! of the TOC itself is stored at the start of the heap, and the RSA
//! `<signature>` and CMS `<x-signature>` both sign that TOC checksum. So the
//! signature is only meaningful if every layer checks out, and
//! [`CheckId::SignatureValid`] checks all of them.

use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom, Write},
    path::Path,
};

use apple_codesign::{AppleCertificate, AppleCodesignError, stapling::Stapler};
use apple_xar::{
    format::XarChecksum,
    reader::XarReader,
    table_of_contents::{ChecksumType, SignatureStyle},
};
use bcder::{Mode, decode::Constructed};
use chrono::{DateTime, Utc};
use cryptographic_message_syntax::{SignedData, asn1::rfc3161::TstInfo};
use x509_certificate::{
    CapturedX509Certificate, DigestAlgorithm, KeyAlgorithm, SignatureAlgorithm,
};

use crate::{
    ArtifactKind, CertKind, Error, Result,
    identity::Suitability,
    sign::pkg::{self as sign_pkg, PkgError},
    tool,
    verify::{Check, CheckId, Report, SignerInfo, Status, VerifyOptions},
};

/// Checks that only make sense once the file has been read, in report order.
const AFTER_FORMAT: &[CheckId] = &[
    CheckId::Signed,
    CheckId::SignatureValid,
    CheckId::CertificateType,
    CheckId::CertificateValidity,
    CheckId::CertificateChain,
    CheckId::Timestamp,
    CheckId::Notarization,
    CheckId::Staple,
];

/// Checks that need a signature.
const AFTER_SIGNED: &[CheckId] = &[
    CheckId::SignatureValid,
    CheckId::CertificateType,
    CheckId::CertificateValidity,
    CheckId::CertificateChain,
    CheckId::Timestamp,
    CheckId::Notarization,
    CheckId::Staple,
];

type Xar = XarReader<BufReader<File>>;

/// Verifies a `.pkg`: signature, certificate type and chain, timestamp,
/// notarization (online unless `offline`), staple, and on macOS `spctl`.
pub fn verify(path: &Path, options: &VerifyOptions) -> Result<Report> {
    let mut report = Report::new(path, ArtifactKind::FlatPackage);
    let file_arg = shell_quote(path);

    let mut xar = match sign_pkg::open(path) {
        Ok(xar) => xar,
        Err(Error::Pkg(PkgError::Malformed { detail })) => {
            report.push(
                Check::fail(
                    CheckId::Format,
                    "Not a valid flat installer package",
                    "Check that the download or build finished, then rebuild the package with `pkgbuild` or `productbuild`.",
                )
                .with_detail(detail),
            );
            skip_all(&mut report, AFTER_FORMAT, "the package couldn't be read");
            return Ok(report);
        }
        Err(e) => return Err(e),
    };

    let format = format_check(&xar);
    let format_ok = format.status == Status::Pass;
    report.push(format);
    if !format_ok {
        skip_all(
            &mut report,
            AFTER_FORMAT,
            "the file isn't an installer package",
        );
        return Ok(report);
    }

    let toc = xar.table_of_contents().clone();
    if toc.signature.is_none() && toc.x_signature.is_none() {
        report.push(Check::fail(
            CheckId::Signed,
            "Not signed",
            format!("Sign it with a Developer ID Installer certificate: `mdmsign sign {file_arg}`"),
        ));
        skip_all(&mut report, AFTER_SIGNED, "the package isn't signed");
        return Ok(report);
    }

    // Collect what we need from the signatures before checking them.
    let cms = match xar.cms_signature() {
        Ok(cms) => Ok(cms),
        Err(e) => Err(format!("the CMS signature can't be parsed ({e})")),
    };
    let leaf = leaf_certificate(&toc, cms.as_ref().ok().and_then(Option::as_ref));
    let kinds: Vec<&str> = [
        toc.signature.as_ref().map(|_| "RSA"),
        toc.x_signature.as_ref().map(|_| "CMS"),
    ]
    .into_iter()
    .flatten()
    .collect();

    let signed = match &leaf {
        Some(cert) => Check::pass(
            CheckId::Signed,
            format!(
                "Signed by {}",
                cert.subject_common_name()
                    .unwrap_or_else(|| "a certificate without a name".into())
            ),
        ),
        None => Check::pass(CheckId::Signed, "Signed"),
    };
    report.push(signed.with_detail(format!("{} signature", kinds.join(" and "))));

    report.push(signature_check(&mut xar, path, &cms, &file_arg));

    let Some(leaf) = leaf else {
        report.push(Check::fail(
            CheckId::CertificateType,
            "The signature doesn't include its certificate",
            format!("Sign the package again: `mdmsign sign --resign {file_arg}`"),
        ));
        skip_all(
            &mut report,
            &AFTER_SIGNED[2..],
            "the signing certificate is missing",
        );
        return Ok(report);
    };
    report.signer = Some(SignerInfo::from_certificate(&leaf));

    let timestamp = timestamp_info(cms.as_ref().ok().and_then(Option::as_ref));

    report.push(certificate_type_check(&leaf));
    report.push(validity_check(&leaf, &timestamp, &file_arg, Utc::now()));
    report.push(chain_check(&leaf));
    report.push(timestamp_check(&timestamp, &file_arg));

    let stapled = stapled_ticket(path);
    let notarization = notarization_check(&mut xar, options, &stapled, &file_arg);
    let notarized = notarization.status == Status::Pass;
    report.push(notarization);
    report.push(staple_check(&stapled, notarized, &file_arg));

    if cfg!(target_os = "macos") && options.system_checks {
        report.push(gatekeeper_check(path, &file_arg));
    }

    Ok(report)
}

fn skip_all(report: &mut Report, ids: &[CheckId], reason: &str) {
    for id in ids {
        report.push(Check::skip(
            *id,
            format!("{}: not checked ({reason})", label(*id)),
        ));
    }
}

fn label(id: CheckId) -> &'static str {
    match id {
        CheckId::Format => "Format",
        CheckId::Signed => "Signature",
        CheckId::SignatureValid => "Signature integrity",
        CheckId::CertificateType => "Certificate type",
        CheckId::CertificateValidity => "Certificate dates",
        CheckId::CertificateChain => "Certificate chain",
        CheckId::Timestamp => "Secure timestamp",
        CheckId::Notarization => "Notarization",
        CheckId::Staple => "Stapled ticket",
        CheckId::Gatekeeper => "Gatekeeper",
        _ => "Check",
    }
}

/// Quotes a path for a copy-pasteable shell command.
fn shell_quote(path: &Path) -> String {
    let text = path.display().to_string();
    if !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./+,:@%".contains(c))
    {
        text
    } else {
        format!("'{}'", text.replace('\'', r"'\''"))
    }
}

fn format_check(xar: &Xar) -> Check {
    let files = match xar.files() {
        Ok(files) => files,
        Err(e) => {
            return Check::fail(
                CheckId::Format,
                "The package's table of contents is damaged",
                "Rebuild the package with `pkgbuild` or `productbuild`.",
            )
            .with_detail(e.to_string());
        }
    };
    let has = |name: &str| files.iter().any(|(path, _)| path == name);
    let layout = if has("Distribution") {
        "product archive"
    } else if has("PackageInfo") {
        "component package"
    } else {
        return Check::fail(
            CheckId::Format,
            "It's a XAR archive, but not an installer package",
            "Installer packages contain a Distribution or PackageInfo file. Build one with `productbuild` or `pkgbuild`.",
        );
    };
    Check::pass(
        CheckId::Format,
        format!("Valid flat installer package ({layout})"),
    )
}

/// The certificate that made the signature. For CMS that's the certificate
/// matching the signer's issuer and serial number; otherwise the first
/// certificate listed, which is where XAR puts the signing certificate.
fn leaf_certificate(
    toc: &apple_xar::table_of_contents::TableOfContents,
    cms: Option<&SignedData>,
) -> Option<CapturedX509Certificate> {
    if let Some(signed_data) = cms
        && let Some(signer) = signed_data.signers().next()
        && let Some((issuer, serial)) = signer.certificate_issuer_and_serial()
        && let Some(cert) = signed_data
            .certificates()
            .find(|c| c.issuer_name() == issuer && c.serial_number_asn1() == serial)
    {
        // Certificates parsed from BER-mode CMS can't be re-encoded as DER
        // (bcder panics), which fingerprinting needs. Re-parse the original
        // bytes as DER.
        return CapturedX509Certificate::from_der(cert.constructed_data().to_vec()).ok();
    }
    [SignatureStyle::Cms, SignatureStyle::Rsa]
        .into_iter()
        .filter_map(|style| toc.find_signature(style))
        .find_map(|sig| sig.x509_certificates().ok()?.into_iter().next())
}

fn signature_check(
    xar: &mut Xar,
    path: &Path,
    cms: &std::result::Result<Option<SignedData>, String>,
    file_arg: &str,
) -> Check {
    let mut problems = Vec::new();
    let mut verified = Vec::new();

    match xar.verify_table_of_contents_checksum() {
        Ok(true) => verified.push("table of contents checksum".to_string()),
        Ok(false) => problems.push("the table of contents doesn't match its checksum".to_string()),
        Err(e) => problems.push(format!(
            "the table of contents checksum can't be read ({e})"
        )),
    }

    match cms {
        Ok(Some(_)) => match xar.verify_cms_signature() {
            Ok(true) => verified.push("CMS signature".into()),
            Ok(false) => problems.push("the CMS signature has no signers".into()),
            Err(e) => problems.push(format!("the CMS signature doesn't match ({e})")),
        },
        Ok(None) => {}
        Err(e) => problems.push(e.clone()),
    }

    if xar.table_of_contents().signature.is_some() {
        match verify_rsa_signature(xar, path) {
            Ok(()) => verified.push("RSA signature".into()),
            Err(e) => problems.push(e),
        }
    }

    match verify_file_data(xar) {
        Ok(summary) => verified.push(summary),
        Err(mut errors) => problems.append(&mut errors),
    }

    if problems.is_empty() {
        Check::pass(CheckId::SignatureValid, "Signature is valid")
            .with_detail(format!("Verified: {}.", verified.join(", ")))
    } else {
        Check::fail(
            CheckId::SignatureValid,
            "The signature doesn't match the package's contents",
            format!(
                "The package was changed after it was signed, or the copy is damaged. Get a fresh copy or rebuild it, then sign it again: `mdmsign sign --resign {file_arg}`"
            ),
        )
        .with_detail(capitalize(&problems.join("; ")))
    }
}

/// Verifies the RSA `<signature>` over the TOC checksum.
///
/// There are two conventions. Apple's tools sign the checksum as an
/// already-computed digest (PKCS #1 v1.5 with the checksum's own hash
/// algorithm). Since the checksum is the hash of the compressed TOC, that's
/// the same as an ordinary signature over the compressed TOC bytes.
/// apple-codesign instead signs the checksum bytes as a message, using the
/// certificate's signature algorithm. Either one is accepted.
fn verify_rsa_signature(xar: &mut Xar, path: &Path) -> std::result::Result<(), String> {
    let (signature, certs) = match xar.rsa_signature() {
        Ok(Some(found)) => found,
        Ok(None) => return Err("the RSA signature is missing".into()),
        Err(e) => return Err(format!("the RSA signature can't be read ({e})")),
    };
    let Some(cert) = certs.first() else {
        return Err("the RSA signature doesn't include its certificate".into());
    };
    if matches!(xar.verify_rsa_checksum_signature(), Ok(true)) {
        return Ok(());
    }

    let algorithm =
        match ChecksumType::try_from(XarChecksum::from(xar.header().checksum_algorithm_id)) {
            Ok(ChecksumType::Sha1) => SignatureAlgorithm::RsaSha1,
            Ok(ChecksumType::Sha256) => SignatureAlgorithm::RsaSha256,
            Ok(ChecksumType::Sha512) => SignatureAlgorithm::RsaSha512,
            _ => {
                return Err("the RSA signature uses a checksum type mdmsign can't verify".into());
            }
        };
    let verified = algorithm
        .resolve_verification_algorithm(KeyAlgorithm::Rsa)
        .map_err(|e| e.to_string())
        .and_then(|verify| {
            let toc = compressed_toc(xar, path).map_err(|e| e.to_string())?;
            cert.verify_signed_data_with_algorithm(toc, &signature, verify)
                .map_err(|e| e.to_string())
        });
    verified.map_err(|e| format!("the RSA signature doesn't match ({e})"))
}

/// The raw, compressed table of contents bytes.
fn compressed_toc(xar: &Xar, path: &Path) -> std::io::Result<Vec<u8>> {
    let header = xar.header();
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(u64::from(header.size)))?;
    let mut toc = Vec::new();
    file.take(header.toc_length_compressed)
        .read_to_end(&mut toc)?;
    Ok(toc)
}

/// Checks each file's data against the checksum recorded in the TOC.
fn verify_file_data(xar: &mut Xar) -> std::result::Result<String, Vec<String>> {
    let files = xar.files().map_err(|e| vec![e.to_string()])?;
    let mut checked = 0;
    let mut problems = Vec::new();
    for (name, file) in files {
        let Some(data) = &file.data else { continue };
        let algorithm = match data.archived_checksum.style {
            ChecksumType::Sha1 => DigestAlgorithm::Sha1,
            ChecksumType::Sha256 => DigestAlgorithm::Sha256,
            ChecksumType::Sha512 => DigestAlgorithm::Sha512,
            other => {
                problems.push(format!(
                    "{name} uses a {other} checksum, which mdmsign can't check"
                ));
                continue;
            }
        };
        let mut hasher = algorithm.digester();
        let result = xar.write_file_data_heap_from_file(
            &file,
            &mut FnWriter(|bytes: &[u8]| hasher.update(bytes)),
        );
        if let Err(e) = result {
            problems.push(format!("the data for {name} can't be read ({e})"));
            continue;
        }
        let actual = hex::encode(hasher.finish().as_ref());
        if actual.eq_ignore_ascii_case(data.archived_checksum.checksum.trim()) {
            checked += 1;
        } else {
            problems.push(format!("{name} has been modified"));
        }
    }
    if problems.is_empty() {
        Ok(match checked {
            1 => "1 file checksum".into(),
            n => format!("{n} file checksums"),
        })
    } else {
        Err(problems)
    }
}

/// Adapts a closure to [`Write`].
struct FnWriter<F>(F);

impl<F: FnMut(&[u8])> Write for FnWriter<F> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (self.0)(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn capitalize(text: &str) -> String {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().chain(chars).collect(),
        None => String::new(),
    }
}

fn certificate_type_check(leaf: &CapturedX509Certificate) -> Check {
    let kind = CertKind::classify(leaf);
    match kind.suitability(ArtifactKind::FlatPackage) {
        Suitability::Suitable => {
            Check::pass(CheckId::CertificateType, format!("{kind} certificate"))
        }
        Suitability::Discouraged { reason } => Check::warn(
            CheckId::CertificateType,
            capitalize(&reason),
            "Sign with a Developer ID Installer certificate.",
        ),
        Suitability::Unsuitable { reason, fix } => {
            Check::fail(CheckId::CertificateType, capitalize(&reason), fix)
        }
    }
}

/// What we know about the signature's secure timestamp.
#[derive(Debug)]
enum TimestampInfo {
    /// A valid timestamp token, and the time it vouches for if readable.
    Valid(Option<DateTime<Utc>>),
    Invalid(String),
    Missing,
}

fn timestamp_info(cms: Option<&SignedData>) -> TimestampInfo {
    let Some(signer) = cms.and_then(|c| c.signers().next()) else {
        return TimestampInfo::Missing;
    };
    let token = match signer.time_stamp_token_signed_data() {
        Ok(Some(token)) => token,
        Ok(None) => return TimestampInfo::Missing,
        Err(e) => return TimestampInfo::Invalid(e.to_string()),
    };
    match signer.verify_time_stamp_token() {
        Ok(Some(())) => {}
        Ok(None) => return TimestampInfo::Invalid("the timestamp token has no signer".into()),
        Err(e) => return TimestampInfo::Invalid(e.to_string()),
    }
    let time = token.signed_content().and_then(|content| {
        Constructed::decode(content, Mode::Ber, TstInfo::take_from)
            .ok()
            .map(|info| DateTime::<Utc>::from(info.gen_time))
    });
    TimestampInfo::Valid(time)
}

fn validity_check(
    leaf: &CapturedX509Certificate,
    timestamp: &TimestampInfo,
    file_arg: &str,
    now: DateTime<Utc>,
) -> Check {
    let not_before = leaf.validity_not_before();
    let not_after = leaf.validity_not_after();
    let date = |t: DateTime<Utc>| t.format("%Y-%m-%d").to_string();
    if now < not_before {
        return Check::fail(
            CheckId::CertificateValidity,
            format!("Certificate isn't valid until {}", date(not_before)),
            "Check this Mac's date and time. If they're right, wait until the certificate becomes valid, or sign with another certificate.",
        );
    }
    if now > not_after {
        if let TimestampInfo::Valid(Some(signed_at)) = timestamp
            && *signed_at >= not_before
            && *signed_at <= not_after
        {
            return Check::pass(
                CheckId::CertificateValidity,
                format!(
                    "Certificate expired on {}, but the package was signed while it was valid",
                    date(not_after)
                ),
            )
            .with_detail(format!(
                "The secure timestamp shows it was signed on {}, so Macs still accept it.",
                signed_at.format("%Y-%m-%d %H:%M:%S UTC")
            ));
        }
        return Check::fail(
            CheckId::CertificateValidity,
            format!("Certificate expired on {}", date(not_after)),
            format!(
                "Renew the Developer ID Installer certificate, then sign again: `mdmsign sign --resign {file_arg}`. Packages signed with a secure timestamp keep working after the certificate expires."
            ),
        );
    }
    let check = Check::pass(
        CheckId::CertificateValidity,
        format!("Certificate valid until {}", date(not_after)),
    );
    let days_left = (not_after - now).num_days();
    if days_left < 30 {
        check.with_detail(format!(
            "It expires in {days_left} day{}. Packages signed with a secure timestamp keep working after that.",
            if days_left == 1 { "" } else { "s" }
        ))
    } else {
        check
    }
}

fn chain_check(leaf: &CapturedX509Certificate) -> Check {
    let issuer = leaf
        .issuer_name()
        .user_friendly_str()
        .unwrap_or_else(|_| "unknown issuer".into());
    if leaf.chains_to_apple_root_ca() {
        Check::pass(CheckId::CertificateChain, "Certificate is issued by Apple")
            .with_detail(format!("Issuer: {issuer}"))
    } else {
        Check::fail(
            CheckId::CertificateChain,
            "Certificate isn't issued by Apple, so Macs won't trust it",
            "Sign with a Developer ID Installer certificate from your Apple Developer account. `mdmsign certs` lists the ones on this Mac.",
        )
        .with_detail(format!("Issuer: {issuer}"))
    }
}

fn timestamp_check(timestamp: &TimestampInfo, file_arg: &str) -> Check {
    let resign = format!("sign again without --no-timestamp: `mdmsign sign --resign {file_arg}`");
    match timestamp {
        TimestampInfo::Valid(Some(time)) => Check::pass(
            CheckId::Timestamp,
            format!("Secure timestamp: {}", time.format("%Y-%m-%d %H:%M:%S UTC")),
        ),
        TimestampInfo::Valid(None) => Check::pass(CheckId::Timestamp, "Has a secure timestamp"),
        TimestampInfo::Invalid(detail) => Check::fail(
            CheckId::Timestamp,
            "The secure timestamp is invalid",
            format!("Re-sign to get a fresh timestamp: {resign}"),
        )
        .with_detail(capitalize(detail)),
        TimestampInfo::Missing => Check::warn(
            CheckId::Timestamp,
            "No secure timestamp",
            format!("Notarization requires a secure timestamp; {resign}"),
        ),
    }
}

/// Size of a notarization ticket stapled to the end of the file, if any.
///
/// The ticket is appended after the XAR data as a `t8lr` terminator record,
/// the ticket, and a `t8lr` ticket record whose length field gives the
/// ticket size (see apple-codesign's `stapling` module).
fn stapled_ticket(path: &Path) -> Option<u32> {
    const MAGIC: &[u8; 4] = b"t8lr";
    const RECORD: u64 = 16;
    const TERMINATOR: u16 = 1;
    const TICKET: u16 = 2;

    let mut file = File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    let read_record = |file: &mut File, offset: u64| -> Option<(u16, u32)> {
        let mut record = [0u8; RECORD as usize];
        file.seek(SeekFrom::Start(offset)).ok()?;
        file.read_exact(&mut record).ok()?;
        if &record[..4] != MAGIC {
            return None;
        }
        let typ = u16::from_le_bytes([record[6], record[7]]);
        let length = u32::from_le_bytes([record[8], record[9], record[10], record[11]]);
        Some((typ, length))
    };

    let (typ, length) = read_record(&mut file, len.checked_sub(RECORD)?)?;
    if typ != TICKET || length == 0 {
        return None;
    }
    let terminator_at = len.checked_sub(RECORD * 2 + u64::from(length))?;
    let (typ, _) = read_record(&mut file, terminator_at)?;
    (typ == TERMINATOR).then_some(length)
}

fn notarization_check(
    xar: &mut Xar,
    options: &VerifyOptions,
    stapled: &Option<u32>,
    file_arg: &str,
) -> Check {
    if options.offline {
        let check = Check::skip(CheckId::Notarization, "Notarization: not checked (offline)");
        return match stapled {
            Some(_) => check.with_detail(
                "A ticket is stapled, which means it was notarized when the ticket was stapled.",
            ),
            None => check,
        };
    }
    let notarize = format!(
        "Notarize it: `mdmsign notarize {file_arg}`. MDM installs don't require notarization, but it's recommended: Macs check it when users open the package themselves."
    );
    let result = match Stapler::new() {
        Ok(stapler) => stapler.lookup_ticket_for_xar(xar),
        Err(e) => Err(e),
    };
    match result {
        Ok(_) => Check::pass(CheckId::Notarization, "Notarized by Apple"),
        Err(AppleCodesignError::NotarizationLookupFailure(code, reason)) => {
            Check::warn(CheckId::Notarization, "Not notarized", notarize)
                .with_detail(format!("Apple's ticket lookup said: {reason} ({code})"))
        }
        Err(
            AppleCodesignError::NotarizationRecordNotInResponse(_)
            | AppleCodesignError::NotarizationRecordNoSignedTicket,
        ) => Check::warn(CheckId::Notarization, "Not notarized", notarize),
        Err(e) => Check::skip(
            CheckId::Notarization,
            "Notarization: couldn't reach Apple to check",
        )
        .with_detail(format!(
            "{e}. Check your internet connection, or pass --offline to skip this check."
        )),
    }
}

fn staple_check(stapled: &Option<u32>, notarized: bool, file_arg: &str) -> Check {
    match stapled {
        Some(bytes) => Check::pass(CheckId::Staple, "Notarization ticket is stapled")
            .with_detail(format!("{bytes}-byte ticket")),
        None if notarized => Check::warn(
            CheckId::Staple,
            "No notarization ticket stapled",
            format!(
                "Staple the ticket so Macs can confirm notarization offline: `mdmsign staple {file_arg}`"
            ),
        ),
        None => Check::warn(
            CheckId::Staple,
            "No notarization ticket stapled",
            format!(
                "Notarize it first; `mdmsign notarize {file_arg}` staples the ticket when Apple accepts it."
            ),
        ),
    }
}

/// Asks macOS's Gatekeeper (`spctl`) whether it would install the package,
/// and adds `pkgutil --check-signature`'s verdict as detail.
fn gatekeeper_check(path: &Path, file_arg: &str) -> Check {
    let output = match tool::run_unchecked(
        "/usr/sbin/spctl",
        [
            "-a".as_ref(),
            "-vv".as_ref(),
            "-t".as_ref(),
            "install".as_ref(),
            path.as_os_str(),
        ],
    ) {
        Ok(output) => output,
        Err(e) => {
            return Check::skip(CheckId::Gatekeeper, "Gatekeeper: couldn't run spctl")
                .with_detail(e.to_string());
        }
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
    let field = |key: &str| {
        text.lines()
            .find_map(|l| l.trim().strip_prefix(key).map(str::to_string))
    };
    let source = field("source=");
    let mut detail: Vec<String> = text
        .lines()
        .skip(1)
        .map(|l| format!("spctl: {}", l.trim()))
        .filter(|l| l.len() > "spctl: ".len())
        .collect();
    if let Some(status) = pkgutil_status(path) {
        detail.push(format!("pkgutil: {status}"));
    }
    let detail = detail.join("\n");
    let accepted = output.status.success()
        && text
            .lines()
            .next()
            .is_some_and(|l| l.trim_end().ends_with(": accepted"));

    let check = if accepted {
        Check::pass(
            CheckId::Gatekeeper,
            format!(
                "Gatekeeper accepts it{}",
                source.map(|s| format!(" ({s})")).unwrap_or_default()
            ),
        )
    } else if source
        .as_deref()
        .is_some_and(|s| s.to_lowercase().contains("unnotarized"))
    {
        Check::warn(
            CheckId::Gatekeeper,
            "Gatekeeper would block it if a user opened it, because it isn't notarized",
            format!(
                "MDM installs aren't affected, but notarizing is recommended: `mdmsign notarize {file_arg}`"
            ),
        )
    } else {
        Check::fail(
            CheckId::Gatekeeper,
            format!(
                "Gatekeeper rejects it{}",
                source.map(|s| format!(": {s}")).unwrap_or_default()
            ),
            "Sign it with a Developer ID Installer certificate issued by Apple, then notarize it. The other checks above say what's wrong.",
        )
    };
    if detail.is_empty() {
        check
    } else {
        check.with_detail(detail)
    }
}

/// The `Status:` line of `pkgutil --check-signature`, if it runs.
fn pkgutil_status(path: &Path) -> Option<String> {
    let output = tool::run_unchecked(
        "/usr/sbin/pkgutil",
        ["--check-signature".as_ref(), path.as_os_str()],
    )
    .ok()?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|l| l.trim().strip_prefix("Status: ").map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_paths_for_the_shell() {
        assert_eq!(
            shell_quote(Path::new("dist/app-1.0.pkg")),
            "dist/app-1.0.pkg"
        );
        assert_eq!(shell_quote(Path::new("My App.pkg")), "'My App.pkg'");
        assert_eq!(shell_quote(Path::new("it's.pkg")), r"'it'\''s.pkg'");
    }

    #[test]
    fn detects_stapled_ticket_trailer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.pkg");
        let ticket = b"pretend ticket";
        let mut data = b"xar!rest of archive".to_vec();
        data.extend_from_slice(
            &apple_codesign::stapling::xar_notarization_trailer(ticket).unwrap(),
        );
        std::fs::write(&path, &data).unwrap();
        assert_eq!(stapled_ticket(&path), Some(ticket.len() as u32));

        std::fs::write(&path, b"xar!no ticket here, just bytes").unwrap();
        assert_eq!(stapled_ticket(&path), None);
    }

    #[test]
    fn expired_certificate_needs_timestamp() {
        let test = crate::testutil::TestIdentity::generate(CertKind::DeveloperIdInstaller);
        let cert = &test.certificate;
        let later = cert.validity_not_after() + chrono::Duration::days(10);
        let during = cert.validity_not_before() + chrono::Duration::hours(1);

        let check = validity_check(cert, &TimestampInfo::Missing, "a.pkg", later);
        assert_eq!(check.status, Status::Fail);
        assert!(check.summary.contains("expired"), "{}", check.summary);

        let check = validity_check(cert, &TimestampInfo::Valid(Some(during)), "a.pkg", later);
        assert_eq!(check.status, Status::Pass);
        assert!(check.detail.unwrap().contains("signed on"));

        let before = cert.validity_not_before() - chrono::Duration::days(1);
        let check = validity_check(cert, &TimestampInfo::Missing, "a.pkg", before);
        assert_eq!(check.status, Status::Fail);
    }
}
