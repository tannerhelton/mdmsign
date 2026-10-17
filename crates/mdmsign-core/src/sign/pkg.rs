//! Signing flat installer packages (`.pkg`).
//!
//! Two backends:
//! - [`NativePkgSigner`]: apple-codesign's XAR signer, for `.p12` identities
//!   on any platform.
//! - [`ProductsignSigner`]: Apple's `productsign`, for Keychain identities on
//!   macOS.
//!
//! Both replace an existing signature when re-signing: apple-codesign writes
//! a fresh table of contents and copies only the file data, and
//! `productsign` documents that it replaces any existing signature. A
//! stapled notarization ticket is dropped along with the old signature,
//! which is correct: the ticket belongs to the old signature.

use std::{
    ffi::OsStr,
    fs::File,
    io::{BufReader, ErrorKind, Read, Seek, SeekFrom},
    path::Path,
};

use apple_codesign::{AppleCodesignError, SigningSettings, UnifiedSigner};
use apple_xar::{reader::XarReader, table_of_contents::SignatureStyle};
use cryptographic_message_syntax::CmsError;
use x509_certificate::CapturedX509Certificate;

use crate::{
    Error, Result, SigningIdentity,
    error::io_error,
    identity::{KeySource, sha1_fingerprint, sha256_fingerprint},
    sign::{APPLE_TIMESTAMP_URL, SignOptions, Signer},
    tool,
};

const PRODUCTSIGN: &str = "/usr/bin/productsign";

const NO_TIMESTAMP_ADVICE: &str = "For local testing you can pass --no-timestamp, but notarization requires a timestamp, so sign again with one before you notarize.";

/// Errors specific to `.pkg` signing and verification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PkgError {
    #[error("the package is malformed: {detail}")]
    Malformed { detail: String },

    #[error("couldn't get a secure timestamp from {url}: {detail}")]
    Timestamp { url: String, detail: String },

    #[error("signing the package failed: {detail}")]
    Signing { detail: String },

    #[error("productsign couldn't find the signing identity \"{name}\" in the Keychain")]
    IdentityNotFound { name: String },

    #[error("macOS didn't let productsign use the private key for \"{name}\": {detail}")]
    KeychainAccessDenied { name: String, detail: String },

    #[error(
        "productsign signed with a different certificate than the one selected: wanted SHA-1 {expected}, got \"{actual_name}\" (SHA-1 {actual})"
    )]
    WrongIdentity {
        expected: String,
        actual: String,
        actual_name: String,
    },

    #[error(
        "productsign always uses Apple's timestamp server, so the custom timestamp URL {url} can't be used with a Keychain identity"
    )]
    CustomTimestampUrl { url: String },

    #[error("productsign failed: {detail}")]
    Productsign { detail: String },
}

impl PkgError {
    pub fn hint(&self) -> Option<String> {
        match self {
            Self::Malformed { .. } => Some(
                "Rebuild the package with `pkgbuild` or `productbuild` and try again. If macOS's own tools can read it (`pkgutil --payload-files <file>`), please report this as an mdmsign bug."
                    .into(),
            ),
            Self::Timestamp { .. } => Some(format!(
                "Timestamping needs an internet connection to reach the timestamp server. Check your connection (and --timestamp-url, if you set one), then retry. {NO_TIMESTAMP_ADVICE}"
            )),
            Self::Signing { .. } => Some(
                "Check that the .p12 holds a Developer ID Installer certificate together with its RSA private key. If it does, run again with the same file and report a bug if it keeps failing."
                    .into(),
            ),
            Self::IdentityNotFound { .. } => Some(
                "Run `mdmsign certs` to list the signing identities on this Mac. The certificate and its private key must both be in your login Keychain; if you only have the certificate, export the identity as a .p12 from the Mac that created it."
                    .into(),
            ),
            Self::KeychainAccessDenied { .. } => Some(
                "Run the command again and click \"Always Allow\" when macOS asks to use the key. Over SSH or in CI there's no prompt: unlock the Keychain first with `security unlock-keychain`, or use a .p12 file (--p12) instead."
                    .into(),
            ),
            Self::WrongIdentity { .. } => Some(
                "Several Keychain identities share this certificate name (often an old and a renewed certificate), and productsign picked the other one. Delete the one you don't want in Keychain Access, or export the right one as a .p12 and pass --p12."
                    .into(),
            ),
            Self::CustomTimestampUrl { .. } => Some(
                "Drop --timestamp-url (and `timestamp_url` from your config), or sign with a .p12 file (--p12), which supports custom timestamp servers."
                    .into(),
            ),
            Self::Productsign { .. } => Some(
                "Check that the package isn't open in another app and that you can write to the output folder. Running `productsign` by hand with the same identity may show more detail."
                    .into(),
            ),
        }
    }
}

/// Signs packages in-process with apple-codesign.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativePkgSigner;

impl Signer for NativePkgSigner {
    fn name(&self) -> &'static str {
        "apple-codesign"
    }

    fn sign(
        &self,
        input: &Path,
        output: &Path,
        identity: &SigningIdentity,
        options: &SignOptions,
    ) -> Result<()> {
        let Some(key) = identity.private_key() else {
            return Err(Error::BackendMismatch {
                backend: "native",
                reason: "it needs the private key in memory, but this identity's key is in the macOS Keychain".into(),
                hint: "Drop --backend native to sign with productsign, or export the identity as a .p12 and pass --p12.".into(),
            });
        };

        let mut settings = SigningSettings::default();
        settings.set_signing_key(key, identity.certificate().clone());
        // Embed Apple's intermediate and root certificates so Macs can build
        // the chain, then anything else the .p12 carried.
        settings.chain_apple_certificates();
        let mut embedded: Vec<String> = std::iter::once(identity.certificate())
            .chain(settings.certificate_chain())
            .map(sha256_fingerprint)
            .collect();
        for cert in identity.chain() {
            let fingerprint = sha256_fingerprint(cert);
            if !embedded.contains(&fingerprint) {
                embedded.push(fingerprint);
                settings.chain_certificate(cert.clone());
            }
        }

        if options.timestamp {
            settings
                .set_time_stamp_url(options.timestamp_url.as_str())
                .map_err(|e| PkgError::Timestamp {
                    url: options.timestamp_url.clone(),
                    detail: format!("it isn't a valid URL ({e})"),
                })?;
        }

        UnifiedSigner::new(settings)
            .sign_xar(input, output)
            .map_err(|e| native_error(e, input, &options.timestamp_url))
    }
}

/// Turns an apple-codesign failure into an error that says what to do.
fn native_error(err: AppleCodesignError, input: &Path, timestamp_url: &str) -> Error {
    let timestamp = |detail: String| {
        Error::from(PkgError::Timestamp {
            url: timestamp_url.to_string(),
            detail,
        })
    };
    match err {
        AppleCodesignError::Xar(apple_xar::Error::Cms(CmsError::TimeStampProtocol(e)))
        | AppleCodesignError::Cms(CmsError::TimeStampProtocol(e)) => timestamp(e.to_string()),
        AppleCodesignError::Xar(apple_xar::Error::Reqwest(e)) | AppleCodesignError::Reqwest(e) => {
            timestamp(e.to_string())
        }
        AppleCodesignError::Xar(apple_xar::Error::Io(e))
            if e.kind() == ErrorKind::UnexpectedEof =>
        {
            PkgError::Malformed {
                detail: "the file ends early; it may be truncated or still downloading".into(),
            }
            .into()
        }
        AppleCodesignError::Xar(e) => match e {
            apple_xar::Error::Scroll(_)
            | apple_xar::Error::Decompress(_)
            | apple_xar::Error::SerdeXml(_)
            | apple_xar::Error::InvalidFileId
            | apple_xar::Error::TableOfContentsCorrupted(_)
            | apple_xar::Error::FileNoData => PkgError::Malformed {
                detail: e.to_string(),
            }
            .into(),
            other => PkgError::Signing {
                detail: other.to_string(),
            }
            .into(),
        },
        AppleCodesignError::Io(e) => io_error("read", input)(e),
        other => PkgError::Signing {
            detail: other.to_string(),
        }
        .into(),
    }
}

/// Signs packages with `/usr/bin/productsign` (macOS, Keychain identities).
///
/// productsign looks identities up by name (a case-insensitive substring of
/// the certificate's common name), not by fingerprint, so several Keychain
/// entries can match, e.g. an old and a renewed certificate. After signing
/// we read back the certificate it used and refuse the result if it isn't
/// the one selected.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProductsignSigner;

impl Signer for ProductsignSigner {
    fn name(&self) -> &'static str {
        "productsign"
    }

    fn sign(
        &self,
        input: &Path,
        output: &Path,
        identity: &SigningIdentity,
        options: &SignOptions,
    ) -> Result<()> {
        let KeySource::Keychain { sha1 } = identity.key() else {
            return Err(Error::BackendMismatch {
                backend: "apple",
                reason: "productsign only uses identities installed in the macOS Keychain".into(),
                hint: "Drop --backend apple to sign the .p12 natively, or import the .p12 into your Keychain and pass --identity.".into(),
            });
        };
        if options.timestamp && options.timestamp_url != APPLE_TIMESTAMP_URL {
            return Err(PkgError::CustomTimestampUrl {
                url: options.timestamp_url.clone(),
            }
            .into());
        }

        let name = identity.common_name();
        let timestamp = if options.timestamp {
            "--timestamp"
        } else {
            "--timestamp=none"
        };
        let result = tool::run_unchecked(
            PRODUCTSIGN,
            [
                OsStr::new("--sign"),
                OsStr::new(&name),
                OsStr::new(timestamp),
                input.as_os_str(),
                output.as_os_str(),
            ],
        )?;
        if !result.status.success() {
            let text = format!(
                "{}\n{}",
                String::from_utf8_lossy(&result.stderr),
                String::from_utf8_lossy(&result.stdout)
            );
            return Err(productsign_error(&name, &text).into());
        }

        let actual = signing_certificate(output)?.ok_or_else(|| PkgError::Productsign {
            detail: "it reported success but the output has no signature".into(),
        })?;
        let actual_sha1 = sha1_fingerprint(&actual);
        if !actual_sha1.eq_ignore_ascii_case(sha1) {
            return Err(PkgError::WrongIdentity {
                expected: sha1.clone(),
                actual: actual_sha1,
                actual_name: actual.subject_common_name().unwrap_or_default(),
            }
            .into());
        }
        Ok(())
    }
}

/// Classifies productsign's error output.
fn productsign_error(name: &str, output: &str) -> PkgError {
    // productsign prefixes real errors with "productsign: error:"; the rest
    // is progress chatter such as "using timestamp authority".
    let errors: Vec<&str> = output
        .lines()
        .map(str::trim)
        .filter(|l| l.contains("error"))
        .map(|l| l.trim_start_matches("productsign: error: "))
        .collect();
    let detail = if errors.is_empty() {
        output.trim().to_string()
    } else {
        errors.join("\n")
    };
    let lower = detail.to_lowercase();

    if lower.contains("could not find appropriate signing identity") {
        return PkgError::IdentityNotFound {
            name: name.to_string(),
        };
    }
    const DENIED: &[&str] = &[
        "user canceled",
        "user cancelled",
        "errsecusercanceled",
        "-128",
        "interaction is not allowed",
        "errsecinteractionnotallowed",
        "-25308",
        "errsecauthfailed",
        "-25293",
        "denied",
        "not permitted",
    ];
    if DENIED.iter().any(|needle| lower.contains(needle)) {
        return PkgError::KeychainAccessDenied {
            name: name.to_string(),
            detail,
        };
    }
    if lower.contains("timestamp") || lower.contains("time stamp") {
        return PkgError::Timestamp {
            url: APPLE_TIMESTAMP_URL.to_string(),
            detail,
        };
    }
    PkgError::Productsign {
        detail: if detail.is_empty() {
            "no error output".into()
        } else {
            detail
        },
    }
}

/// Opens a package's XAR archive and parses its table of contents.
///
/// The header and the sizes recorded in the table of contents are checked
/// against the file size first: apple-xar trusts them when allocating, so a
/// damaged file could otherwise abort the process.
pub(crate) fn open(path: &Path) -> Result<XarReader<BufReader<File>>> {
    let malformed = |detail: &str| -> Error {
        PkgError::Malformed {
            detail: detail.to_string(),
        }
        .into()
    };
    let mut file = File::open(path).map_err(io_error("read", path))?;
    let len = file.metadata().map_err(io_error("read", path))?.len();

    let mut header = [0u8; XAR_HEADER_LEN];
    if let Err(e) = file.read_exact(&mut header) {
        return Err(if e.kind() == ErrorKind::UnexpectedEof {
            malformed("the file is too short to be a package")
        } else {
            io_error("read", path)(e)
        });
    }
    if &header[..4] != b"xar!" {
        return Err(malformed("it doesn't start with a XAR header"));
    }
    let header_len = u64::from(u16::from_be_bytes([header[4], header[5]]));
    let toc_compressed = u64::from_be_bytes(header[8..16].try_into().expect("8 bytes"));
    let toc_uncompressed = u64::from_be_bytes(header[16..24].try_into().expect("8 bytes"));
    if header_len < XAR_HEADER_LEN as u64 {
        return Err(malformed("the XAR header is too short"));
    }
    if header_len
        .checked_add(toc_compressed)
        .is_none_or(|end| end > len)
    {
        return Err(malformed(
            "the table of contents runs past the end of the file; it may be truncated or still downloading",
        ));
    }
    if toc_uncompressed > MAX_TOC_LEN {
        return Err(malformed(
            "the XAR header claims an implausibly large table of contents",
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(io_error("read", path))?;

    let xar = XarReader::new(BufReader::new(file)).map_err(|e| {
        Error::from(PkgError::Malformed {
            detail: describe_xar_error(&e),
        })
    })?;

    let heap_len = len.saturating_sub(xar.heap_start_offset());
    let toc = xar.table_of_contents();
    let regions = std::iter::once(("checksum", toc.checksum.offset, toc.checksum.size)).chain(
        toc.signatures()
            .into_iter()
            .map(|sig| ("signature", sig.offset, sig.size)),
    );
    for (what, offset, size) in regions {
        if offset.checked_add(size).is_none_or(|end| end > heap_len) {
            return Err(malformed(&format!(
                "the {what} data runs past the end of the file; it may be truncated or still downloading"
            )));
        }
    }
    Ok(xar)
}

/// Size of the fixed part of a XAR header.
const XAR_HEADER_LEN: usize = 28;

/// Largest table of contents we'll decompress. Real ones are kilobytes.
const MAX_TOC_LEN: u64 = 64 * 1024 * 1024;

/// Describes a XAR parsing error in words.
pub(crate) fn describe_xar_error(err: &apple_xar::Error) -> String {
    match err {
        apple_xar::Error::Io(e) if e.kind() == ErrorKind::UnexpectedEof => {
            "the file ends early; it may be truncated or still downloading".into()
        }
        apple_xar::Error::Scroll(_) | apple_xar::Error::Io(_) => {
            format!("the XAR header can't be read ({err})")
        }
        apple_xar::Error::Decompress(_) => {
            format!("the table of contents can't be decompressed ({err})")
        }
        apple_xar::Error::SerdeXml(_) => {
            format!("the table of contents isn't valid ({err})")
        }
        other => other.to_string(),
    }
}

/// The certificate that made a package's signature: the first certificate
/// of the CMS signature if there is one, else of the RSA signature.
pub(crate) fn signing_certificate(path: &Path) -> Result<Option<CapturedX509Certificate>> {
    let xar = open(path)?;
    let toc = xar.table_of_contents();
    let Some(signature) = toc
        .find_signature(SignatureStyle::Cms)
        .or_else(|| toc.find_signature(SignatureStyle::Rsa))
    else {
        return Ok(None);
    };
    let certs = signature
        .x509_certificates()
        .map_err(|e| PkgError::Malformed {
            detail: format!("the signature's certificates can't be read ({e})"),
        })?;
    Ok(certs.into_iter().next())
}

/// Whether the package already has a signature.
pub fn is_signed(path: &Path) -> Result<bool> {
    let xar = open(path)?;
    let toc = xar.table_of_contents();
    Ok(toc.signature.is_some() || toc.x_signature.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_productsign_errors() {
        let name = "Developer ID Installer: Example (ABCDE12345)";
        assert!(matches!(
            productsign_error(
                name,
                "productsign: error: Could not find appropriate signing identity for “Developer ID Installer: Example (ABCDE12345)”.\n"
            ),
            PkgError::IdentityNotFound { .. }
        ));
        assert!(matches!(
            productsign_error(
                name,
                "productsign: using timestamp authority for signature\nproductsign: error: Signing failed: User canceled the operation. (-128)\n"
            ),
            PkgError::KeychainAccessDenied { .. }
        ));
        let err = productsign_error(
            name,
            "productsign: using timestamp authority for signature\nproductsign: error: Timestamping failed: The timestamp service is not available.\n",
        );
        assert!(matches!(err, PkgError::Timestamp { .. }), "{err:?}");
        assert!(err.hint().unwrap().contains("--no-timestamp"));
        let err = productsign_error(
            name,
            "productsign: using timestamp authority for signature\nproductsign: error: Something unexpected.\n",
        );
        let PkgError::Productsign { detail } = err else {
            panic!("expected a generic productsign error");
        };
        assert_eq!(detail, "Something unexpected.");
    }

    #[test]
    fn rejects_non_xar() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.pkg");
        std::fs::write(&path, b"xar!\0\x1c\0\x01garbage").unwrap();
        let err = is_signed(&path).unwrap_err();
        assert!(
            matches!(err, Error::Pkg(PkgError::Malformed { .. })),
            "{err:?}"
        );
        assert!(err.hint().unwrap().contains("pkgbuild"));
    }

    #[test]
    fn fixture_is_unsigned() {
        assert!(!is_signed(&crate::testutil::fixture("unsigned.pkg")).unwrap());
    }
}
