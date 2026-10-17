//! Signing configuration profiles (`.mobileconfig`) as CMS SignedData.
//!
//! A signed profile is a DER (or BER) CMS `ContentInfo` whose `SignedData`
//! carries the property list inline. Two backends:
//! - [`NativeProfileSigner`]: the `cryptographic-message-syntax` crate, for
//!   `.p12` identities on any platform.
//! - [`SecurityCmsSigner`]: `security cms -S`, for Keychain identities on
//!   macOS.
//!
//! Both refuse to sign anything that isn't a configuration profile, and both
//! unwrap an existing signature first when re-signing, so the signed content
//! is always the bare property list. Profiles are never timestamped.

use std::{
    io::Read,
    path::{Path, PathBuf},
};

use apple_codesign::{AppleCertificate, cryptography::InMemoryPrivateKey};
use bytes::Bytes;
use cryptographic_message_syntax::{
    Oid, SignedData, SignedDataBuilder, SignerBuilder, asn1::rfc5652::OID_ID_DATA,
};
use x509_certificate::CapturedX509Certificate;

use crate::{
    Error, Result, SigningIdentity,
    error::io_error,
    identity::{KeySource, sha1_fingerprint},
    sign::{SignOptions, Signer},
    tool::{self, ToolError},
};

const SECURITY: &str = "/usr/bin/security";

/// The keys every configuration profile's top-level dictionary must have,
/// besides `PayloadType`.
const REQUIRED_KEYS: &[&str] = &["PayloadIdentifier", "PayloadUUID", "PayloadVersion"];

/// Errors specific to profile signing and verification.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProfileError {
    #[error("the profile isn't a valid property list: {detail}")]
    InvalidPlist { detail: String },

    #[error("the profile's top level is {found}, not a dictionary")]
    NotADictionary { found: &'static str },

    #[error("{}", match payload_type {
        Some(found) => format!("this isn't a configuration profile: its top-level PayloadType is \"{found}\", not \"Configuration\""),
        None => "this isn't a configuration profile: its top-level dictionary has no PayloadType".to_string(),
    })]
    NotAConfigurationProfile { payload_type: Option<String> },

    #[error("the profile is missing required key{}: {}", if keys.len() == 1 { "" } else { "s" }, keys.join(", "))]
    MissingKeys { keys: Vec<&'static str> },

    #[error("the profile's existing signature can't be read: {detail}")]
    UnreadableSignature { detail: String },

    #[error("the signed profile doesn't contain the profile itself (detached signature)")]
    DetachedContent,

    #[error("couldn't build the profile signature: {detail}")]
    SigningFailed { detail: String },

    #[error("`security cms` couldn't sign with \"{identity}\": {detail}")]
    KeychainSigningFailed { identity: String, detail: String },

    #[error(
        "`security cms` signed with a different certificate ({found}) than the one requested ({expected})"
    )]
    WrongSigner { expected: String, found: String },
}

impl ProfileError {
    pub fn hint(&self) -> Option<String> {
        match self {
            Self::InvalidPlist { .. } | Self::NotADictionary { .. } => Some(
                "Check the profile with `plutil -lint <file>` and fix any errors it reports. A profile is an XML property list whose top level is a <dict>."
                    .into(),
            ),
            Self::NotAConfigurationProfile { payload_type: Some(found) } => Some(format!(
                "This looks like a single \"{found}\" payload rather than a whole profile. Put it inside the PayloadContent array of a profile whose PayloadType is Configuration, or export the complete profile from your MDM, Apple Configurator or iMazing Profile Editor."
            )),
            Self::NotAConfigurationProfile { payload_type: None } => Some(
                "Add <key>PayloadType</key><string>Configuration</string> to the top-level dictionary, or export the complete profile from your MDM, Apple Configurator or iMazing Profile Editor. `plutil -p <file>` shows what's there."
                    .into(),
            ),
            Self::MissingKeys { .. } => Some(
                "Add the missing keys to the profile's top-level dictionary (PayloadUUID is a UUID such as the output of `uuidgen`; PayloadVersion is the integer 1), then check it with `plutil -lint <file>`."
                    .into(),
            ),
            Self::UnreadableSignature { .. } => Some(
                "The file looks signed but its signature data is damaged. Get a fresh copy of the profile (ideally the unsigned original) and sign that."
                    .into(),
            ),
            Self::DetachedContent => Some(
                "mdmsign can't recover the profile from a detached signature. Sign the original unsigned .mobileconfig instead."
                    .into(),
            ),
            Self::SigningFailed { .. } => Some(
                "Check that the .p12 contains a supported RSA or ECDSA key. Run `mdmsign certs` to inspect it, and report a bug if this keeps happening."
                    .into(),
            ),
            Self::KeychainSigningFailed { .. } => Some(
                "Check that the certificate and its private key are in your login keychain (`security find-identity -v` lists usable identities), that the keychain is unlocked, and that you chose \"Allow\" if macOS asked for access. Alternatively export the identity as a .p12 and pass --p12."
                    .into(),
            ),
            Self::WrongSigner { .. } => Some(
                "Several Keychain identities look alike. Remove expired or duplicate copies of the certificate from Keychain Access, or export the right one as a .p12 and pass --p12."
                    .into(),
            ),
        }
    }
}

/// Facts about a valid configuration profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileSummary {
    pub identifier: String,
    pub uuid: String,
    pub display_name: Option<String>,
    /// Number of payloads in `PayloadContent`.
    pub payload_count: usize,
    /// True for a binary (`bplist00`) property list, false for XML.
    pub binary: bool,
}

/// Whether `data` starts like a DER/BER CMS `ContentInfo`.
///
/// This matches [`crate::ArtifactKind::detect`]: a SEQUENCE tag followed by an
/// indefinite or long-form length. Property lists never start this way.
pub fn looks_signed(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x30 && matches!(data[1], 0x80..=0x84)
}

/// Whether the profile is already CMS-signed.
pub fn is_signed(path: &Path) -> Result<bool> {
    let mut head = Vec::with_capacity(2);
    std::fs::File::open(path)
        .map_err(io_error("read", path))?
        .take(2)
        .read_to_end(&mut head)
        .map_err(io_error("read", path))?;
    Ok(looks_signed(&head))
}

/// Parses a CMS signature, mapping failures to a [`ProfileError`].
pub fn parse_signed_data(data: &[u8]) -> Result<SignedData, ProfileError> {
    SignedData::parse_ber(data).map_err(|e| ProfileError::UnreadableSignature {
        detail: e.to_string(),
    })
}

/// The profile embedded in a signed profile.
pub fn signed_content(signed: &SignedData) -> Result<Vec<u8>, ProfileError> {
    signed
        .signed_content()
        .map(<[u8]>::to_vec)
        .ok_or(ProfileError::DetachedContent)
}

/// Checks that `content` is a configuration profile: a property list whose
/// top level is a dictionary with `PayloadType` = `Configuration`,
/// `PayloadIdentifier`, `PayloadUUID` and `PayloadVersion`.
pub fn validate_content(content: &[u8]) -> Result<ProfileSummary, ProfileError> {
    let value = plist::Value::from_reader(std::io::Cursor::new(content)).map_err(|e| {
        ProfileError::InvalidPlist {
            detail: e.to_string(),
        }
    })?;
    let Some(dict) = value.as_dictionary() else {
        return Err(ProfileError::NotADictionary {
            found: describe_value(&value),
        });
    };
    let payload_type = dict.get("PayloadType").map(|v| match v.as_string() {
        Some(s) => s.to_string(),
        None => format!("({})", describe_value(v)),
    });
    if payload_type.as_deref() != Some("Configuration") {
        return Err(ProfileError::NotAConfigurationProfile { payload_type });
    }
    let missing: Vec<&'static str> = REQUIRED_KEYS
        .iter()
        .copied()
        .filter(|k| !dict.contains_key(k))
        .collect();
    if !missing.is_empty() {
        return Err(ProfileError::MissingKeys { keys: missing });
    }
    let string = |key: &str| {
        dict.get(key)
            .and_then(plist::Value::as_string)
            .map(str::to_string)
    };
    Ok(ProfileSummary {
        identifier: string("PayloadIdentifier").unwrap_or_default(),
        uuid: string("PayloadUUID").unwrap_or_default(),
        display_name: string("PayloadDisplayName"),
        payload_count: dict
            .get("PayloadContent")
            .and_then(plist::Value::as_array)
            .map_or(0, Vec::len),
        binary: content.starts_with(b"bplist00"),
    })
}

fn describe_value(value: &plist::Value) -> &'static str {
    match value {
        plist::Value::Array(_) => "an array",
        plist::Value::Dictionary(_) => "a dictionary",
        plist::Value::Boolean(_) => "a boolean",
        plist::Value::Data(_) => "data",
        plist::Value::Date(_) => "a date",
        plist::Value::Real(_) => "a number",
        plist::Value::Integer(_) => "an integer",
        plist::Value::String(_) => "a string",
        plist::Value::Uid(_) => "a UID",
        _ => "an unknown value",
    }
}

/// Reads the profile to sign: the file itself if unsigned, or the profile
/// inside the existing signature. The result is validated.
fn content_to_sign(input: &Path) -> Result<(Vec<u8>, bool)> {
    let data = std::fs::read(input).map_err(io_error("read", input))?;
    let (content, was_signed) = if looks_signed(&data) {
        (signed_content(&parse_signed_data(&data)?)?, true)
    } else {
        (data, false)
    };
    validate_content(&content)?;
    Ok((content, was_signed))
}

/// Certificates to embed besides the signing certificate: the identity's own
/// chain and, when the certificate chains to an Apple root, Apple's
/// intermediates. Roots are left out; Macs already have them.
fn chain_to_embed(identity: &SigningIdentity) -> Vec<CapturedX509Certificate> {
    let mut certs: Vec<CapturedX509Certificate> = identity
        .chain()
        .iter()
        .filter(|c| !c.is_apple_root_ca())
        .cloned()
        .collect();
    if let Some(chain) = identity.certificate().apple_root_certificate_chain() {
        for cert in chain.into_iter().skip(1) {
            if !cert.is_apple_root_ca() && !certs.contains(&cert) {
                certs.push(cert);
            }
        }
    }
    certs
}

/// Builds a DER CMS SignedData over `content` with `key` and the identity's
/// certificates.
pub(crate) fn build_signed_profile(
    content: Vec<u8>,
    key: &InMemoryPrivateKey,
    identity: &SigningIdentity,
) -> Result<Vec<u8>, ProfileError> {
    let id_data = Oid(Bytes::copy_from_slice(OID_ID_DATA.as_ref()));
    SignedDataBuilder::default()
        .content_inline(content)
        .content_type(id_data)
        .signer(SignerBuilder::new(key, identity.certificate().clone()))
        .certificate(identity.certificate().clone())
        .certificates(chain_to_embed(identity).into_iter())
        .build_der()
        .map_err(|e| ProfileError::SigningFailed {
            detail: e.to_string(),
        })
}

/// Signs profiles in-process with the `cryptographic-message-syntax` crate.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeProfileSigner;

impl Signer for NativeProfileSigner {
    fn name(&self) -> &'static str {
        "cms"
    }

    fn sign(
        &self,
        input: &Path,
        output: &Path,
        identity: &SigningIdentity,
        _options: &SignOptions,
    ) -> Result<()> {
        let Some(key) = identity.private_key() else {
            return Err(Error::BackendMismatch {
                backend: "native",
                reason: "it needs the private key in memory, but this identity's key is in the macOS Keychain".into(),
                hint: "Drop --backend native to sign with Apple's tools, or export the identity as a .p12 and pass --p12.".into(),
            });
        };
        let (content, _) = content_to_sign(input)?;
        let der = build_signed_profile(content, key, identity)?;
        std::fs::write(output, der).map_err(io_error("write", output))?;
        Ok(())
    }
}

/// Signs profiles with `security cms -S` (macOS, Keychain identities).
///
/// The identity is selected by the certificate's subject key identifier
/// (`-Z`), which pins the exact key pair. If the certificate has no subject
/// key identifier, or `security` can't find it that way, the common name
/// (`-N`) is used instead. Either way the result is checked to be signed by
/// the requested certificate. `security cms` adds the certificate chain
/// (without the root) itself.
#[derive(Clone, Copy, Debug, Default)]
pub struct SecurityCmsSigner;

impl Signer for SecurityCmsSigner {
    fn name(&self) -> &'static str {
        "security cms"
    }

    fn sign(
        &self,
        input: &Path,
        output: &Path,
        identity: &SigningIdentity,
        _options: &SignOptions,
    ) -> Result<()> {
        let KeySource::Keychain { sha1 } = identity.key() else {
            return Err(Error::BackendMismatch {
                backend: "apple",
                reason: "Apple's signing tools only use identities installed in the macOS Keychain".into(),
                hint: "Drop --backend apple to sign the .p12 natively, or import the .p12 into your Keychain and pass --identity.".into(),
            });
        };

        let (content, was_signed) = content_to_sign(input)?;
        // `security cms` reads a file, so give it the bare profile when
        // re-signing. The temporary directory is removed on drop.
        let unwrapped;
        let source: PathBuf = if was_signed {
            unwrapped = tempfile::Builder::new()
                .prefix(".mdmsign-")
                .tempdir()
                .map_err(io_error(
                    "create a temporary directory in",
                    std::env::temp_dir(),
                ))?;
            let path = unwrapped.path().join("profile.mobileconfig");
            std::fs::write(&path, &content).map_err(io_error("write", &path))?;
            path
        } else {
            input.to_path_buf()
        };

        let name = identity.common_name();
        let mut selectors = Vec::new();
        if let Some(ski) = subject_key_identifier(identity.certificate()) {
            selectors.push(["-Z".to_string(), hex::encode_upper(ski)]);
        }
        selectors.push(["-N".to_string(), name.clone()]);

        let mut last_error = None;
        for selector in &selectors {
            match run_security_cms(selector, &source, output) {
                Ok(()) => {
                    last_error = None;
                    break;
                }
                Err(SecurityCmsError::NotFound(detail)) => last_error = Some(detail),
                Err(SecurityCmsError::Failed(detail)) => {
                    return Err(ProfileError::KeychainSigningFailed {
                        identity: name,
                        detail,
                    }
                    .into());
                }
                Err(SecurityCmsError::Tool(e)) => return Err(e.into()),
            }
        }
        if let Some(detail) = last_error {
            return Err(ProfileError::KeychainSigningFailed {
                identity: name,
                detail,
            }
            .into());
        }

        // Make sure `security` picked the identity we asked for: a name can
        // match an expired copy of the same certificate.
        let data = std::fs::read(output).map_err(io_error("read", output))?;
        let signed = parse_signed_data(&data)?;
        let found = signed
            .signers()
            .next()
            .and_then(|signer| signer_certificate(&signed, signer))
            .map(|cert| sha1_fingerprint(&cert))
            .unwrap_or_else(|| "none".into());
        if !found.eq_ignore_ascii_case(sha1) {
            return Err(ProfileError::WrongSigner {
                expected: sha1.clone(),
                found,
            }
            .into());
        }
        Ok(())
    }
}

enum SecurityCmsError {
    /// `security` couldn't find the identity with this selector.
    NotFound(String),
    /// Any other `security` failure.
    Failed(String),
    Tool(ToolError),
}

fn run_security_cms(
    selector: &[String; 2],
    input: &Path,
    output: &Path,
) -> Result<(), SecurityCmsError> {
    let mut args: Vec<std::ffi::OsString> = ["cms", "-S", "-H", "SHA256", "-G"]
        .into_iter()
        .map(Into::into)
        .collect();
    args.extend(selector.iter().map(Into::into));
    args.extend(["-i".into(), input.into(), "-o".into(), output.into()]);
    match tool::run(SECURITY, &args) {
        Ok(_) => Ok(()),
        Err(ToolError::Failed { stderr, .. }) => {
            let detail = stderr.trim().to_string();
            if detail.contains("could not find signing identity") {
                Err(SecurityCmsError::NotFound(detail))
            } else {
                Err(SecurityCmsError::Failed(detail))
            }
        }
        Err(e) => Err(SecurityCmsError::Tool(e)),
    }
}

/// The certificate's subject key identifier extension (2.5.29.14), if any.
pub(crate) fn subject_key_identifier(cert: &CapturedX509Certificate) -> Option<Vec<u8>> {
    const OID_SUBJECT_KEY_IDENTIFIER: &[u8] = &[85, 29, 14];
    let raw: &x509_certificate::rfc5280::Certificate = cert.as_ref();
    let extension = raw
        .iter_extensions()
        .find(|e| e.id.as_ref() == OID_SUBJECT_KEY_IDENTIFIER)?;
    let value = extension.value.to_bytes();
    // The extension value is a DER OCTET STRING holding the key identifier.
    match value.as_ref() {
        [0x04, len, rest @ ..] if usize::from(*len) == rest.len() && *len < 0x80 => {
            Some(rest.to_vec())
        }
        _ => None,
    }
}

/// Finds the certificate a signer used among those embedded in `signed`.
///
/// Matching is the same as `cryptographic-message-syntax` uses to pick the
/// key it verifies the signature with, so the certificate returned here is
/// the one whose key the signature was checked against. Returns `None` if no
/// certificate matches, or if more than one does: with several candidates a
/// crafted file could have the signature checked against one certificate
/// while the type and chain checks look at another.
///
/// The result is re-parsed with [`reparse_der`], so it can be fingerprinted.
pub fn signer_certificate(
    signed: &SignedData,
    signer: &cryptographic_message_syntax::SignerInfo,
) -> Option<CapturedX509Certificate> {
    let (issuer, serial) = signer.certificate_issuer_and_serial()?;
    let mut matches = signed.certificates().filter(|cert| {
        x509_certificate::certificate::certificate_is_subset_of(
            serial,
            issuer,
            cert.serial_number_asn1(),
            cert.issuer_name(),
        )
    });
    let found = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(reparse_der(found))
}

/// Re-parses a certificate taken from a CMS structure in DER mode.
///
/// `SignedData` captures embedded certificates in BER mode, and
/// re-encoding them as DER (which fingerprinting does) panics inside
/// `bcder`. Parsing the original bytes again as DER avoids that; if they
/// aren't valid DER the certificate is returned as is.
pub fn reparse_der(cert: &CapturedX509Certificate) -> CapturedX509Certificate {
    CapturedX509Certificate::from_der(cert.constructed_data().to_vec())
        .unwrap_or_else(|_| cert.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CertKind, Secret, testutil};

    fn identity() -> SigningIdentity {
        let test = testutil::TestIdentity::generate(CertKind::DeveloperIdApplication);
        SigningIdentity::from_p12(&test.p12, &Secret::new(&test.password), "test.p12").unwrap()
    }

    #[test]
    fn detects_signed_and_unsigned() {
        assert!(looks_signed(&[0x30, 0x80, 0x06]));
        assert!(looks_signed(&[0x30, 0x82, 0x10, 0x00]));
        assert!(!looks_signed(testutil::SAMPLE_PROFILE.as_bytes()));
        assert!(!looks_signed(b"bplist00"));
        assert!(!looks_signed(&[0x30]));
    }

    #[test]
    fn validates_sample_profile() {
        let summary = validate_content(testutil::SAMPLE_PROFILE.as_bytes()).unwrap();
        assert_eq!(summary.identifier, "com.example.mdmsign.test");
        assert_eq!(
            summary.display_name.as_deref(),
            Some("mdmsign test profile")
        );
        assert_eq!(summary.payload_count, 0);
        assert!(!summary.binary);
    }

    #[test]
    fn validates_binary_profile() {
        let value =
            plist::Value::from_reader(std::io::Cursor::new(testutil::SAMPLE_PROFILE)).unwrap();
        let mut binary = Vec::new();
        value.to_writer_binary(&mut binary).unwrap();
        assert!(validate_content(&binary).unwrap().binary);
    }

    #[test]
    fn rejects_non_profiles_with_hints() {
        let err = validate_content(b"not a plist").unwrap_err();
        assert!(matches!(err, ProfileError::InvalidPlist { .. }), "{err:?}");
        assert!(err.hint().unwrap().contains("plutil -lint"));

        let err =
            validate_content(br#"<?xml version="1.0"?><plist version="1.0"><array/></plist>"#)
                .unwrap_err();
        assert_eq!(
            err.to_string(),
            "the profile's top level is an array, not a dictionary"
        );

        let err = validate_content(
            br#"<?xml version="1.0"?><plist version="1.0"><dict><key>PayloadType</key><string>com.apple.wifi.managed</string></dict></plist>"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("com.apple.wifi.managed"), "{err}");
        assert!(err.hint().unwrap().contains("PayloadContent"));

        let err = validate_content(
            br#"<?xml version="1.0"?><plist version="1.0"><dict><key>Foo</key><true/></dict></plist>"#,
        )
        .unwrap_err();
        assert!(err.to_string().contains("no PayloadType"), "{err}");

        let err = validate_content(
            br#"<?xml version="1.0"?><plist version="1.0"><dict><key>PayloadType</key><string>Configuration</string><key>PayloadIdentifier</key><string>x</string></dict></plist>"#,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            "the profile is missing required keys: PayloadUUID, PayloadVersion"
        );
        assert!(err.hint().unwrap().contains("uuidgen"));
    }

    #[test]
    fn builds_signature_that_round_trips() {
        let identity = identity();
        let key = identity.private_key().unwrap();
        let der =
            build_signed_profile(testutil::SAMPLE_PROFILE.as_bytes().to_vec(), key, &identity)
                .unwrap();
        assert!(looks_signed(&der));
        let signed = parse_signed_data(&der).unwrap();
        assert_eq!(
            signed_content(&signed).unwrap(),
            testutil::SAMPLE_PROFILE.as_bytes()
        );
        let signer = signed.signers().next().unwrap();
        signer.verify_signature_with_signed_data(&signed).unwrap();
        signer
            .verify_message_digest_with_signed_data(&signed)
            .unwrap();
        let found = signer_certificate(&signed, signer).unwrap();
        assert_eq!(
            found.constructed_data(),
            identity.certificate().constructed_data()
        );
        // Certificates from a parsed signature can be fingerprinted.
        assert_eq!(sha1_fingerprint(&found), identity.sha1_fingerprint());
    }

    /// A signature carrying a second certificate with the same issuer and
    /// serial number as the signer's. Test certificates are self-signed with
    /// serial 1, so any two of the same type collide.
    fn signed_with_decoy() -> Vec<u8> {
        let signer = identity();
        let decoy = testutil::TestIdentity::generate(CertKind::DeveloperIdApplication);
        assert_ne!(
            decoy.certificate.public_key_data(),
            signer.certificate().public_key_data()
        );
        let id_data = Oid(Bytes::copy_from_slice(OID_ID_DATA.as_ref()));
        SignedDataBuilder::default()
            .content_inline(testutil::SAMPLE_PROFILE.as_bytes().to_vec())
            .content_type(id_data)
            .signer(SignerBuilder::new(
                signer.private_key().unwrap(),
                signer.certificate().clone(),
            ))
            .certificate(decoy.certificate)
            .build_der()
            .unwrap()
    }

    #[test]
    fn ambiguous_signer_certificate_is_not_picked() {
        let der = signed_with_decoy();
        let signed = parse_signed_data(&der).unwrap();
        assert_eq!(signed.certificates().count(), 2);
        let signer = signed.signers().next().unwrap();
        assert!(signer_certificate(&signed, signer).is_none());
    }

    #[test]
    fn ambiguous_signer_certificate_fails_verification() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("decoy.mobileconfig");
        std::fs::write(&path, signed_with_decoy()).unwrap();
        let report =
            crate::verify::verify_file(&path, &crate::verify::VerifyOptions::post_sign()).unwrap();
        let check = report
            .check(crate::verify::CheckId::SignatureValid)
            .unwrap();
        assert_eq!(check.status, crate::verify::Status::Fail, "{check:?}");
        assert!(report.signer.is_none());
        assert!(!report.mdm_ready);
    }

    #[test]
    fn native_signer_refuses_non_profiles() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("x.mobileconfig");
        std::fs::write(&input, b"<?xml version=\"1.0\"?><plist><dict/></plist>").unwrap();
        let err = NativeProfileSigner
            .sign(
                &input,
                &dir.path().join("out.mobileconfig"),
                &identity(),
                &SignOptions::default(),
            )
            .unwrap_err();
        assert!(
            matches!(
                err,
                Error::Profile(ProfileError::NotAConfigurationProfile { .. })
            ),
            "{err:?}"
        );
        assert!(!dir.path().join("out.mobileconfig").exists());
    }

    #[test]
    fn reads_subject_key_identifier() {
        // Generated test certificates may or may not carry the extension;
        // whatever is returned must be a plausible key identifier.
        let identity = identity();
        if let Some(ski) = subject_key_identifier(identity.certificate()) {
            assert!(!ski.is_empty() && ski.len() <= 64);
        }
    }

    #[test]
    fn every_error_has_a_hint() {
        let errors = [
            ProfileError::InvalidPlist { detail: "x".into() },
            ProfileError::NotADictionary { found: "an array" },
            ProfileError::NotAConfigurationProfile { payload_type: None },
            ProfileError::NotAConfigurationProfile {
                payload_type: Some("x".into()),
            },
            ProfileError::MissingKeys {
                keys: vec!["PayloadUUID"],
            },
            ProfileError::UnreadableSignature { detail: "x".into() },
            ProfileError::DetachedContent,
            ProfileError::SigningFailed { detail: "x".into() },
            ProfileError::KeychainSigningFailed {
                identity: "x".into(),
                detail: "x".into(),
            },
            ProfileError::WrongSigner {
                expected: "a".into(),
                found: "b".into(),
            },
        ];
        for err in errors {
            assert!(err.hint().is_some(), "{err:?}");
        }
    }
}
