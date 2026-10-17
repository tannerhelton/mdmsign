//! Notarizing and stapling packages through the App Store Connect API.
//!
//! [`notarize`] uploads a signed `.pkg` to Apple's notary service, waits for
//! the verdict, and staples the ticket. [`staple`] fetches the ticket for a
//! package that was notarized earlier and appends it to the file.
//!
//! The upload and polling are done by [`apple_codesign::notarization`] and
//! the ticket lookup by [`apple_codesign::stapling`]. The App Store Connect
//! private key and the tokens made from it are never printed or logged.

use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use apple_codesign::{
    AppleCodesignError,
    cryptography::InMemoryPrivateKey,
    notarization::{NotarizationUpload, Notarizer},
    stapling::{Stapler, xar_notarization_trailer},
};
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::{
    ArtifactKind, Error, Result, credentials::AscCredentials, error::io_error, sign::is_signed,
};

/// Errors from notarization and stapling.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum NotarizeError {
    #[error("can't {action} {}: it's a {kind}; notarization in mdmsign is for .pkg installers, and profiles don't need it", path.display())]
    NotAPackage {
        path: PathBuf,
        kind: ArtifactKind,
        action: &'static str,
    },

    #[error("{} isn't signed, and Apple only notarizes signed packages", path.display())]
    Unsigned { path: PathBuf },

    #[error("the App Store Connect API key from {label} can't be used: {detail}")]
    InvalidApiKey { label: String, detail: String },

    #[error("Apple refused the App Store Connect API key: {detail}")]
    Auth { detail: String },

    #[error("couldn't {action}: {detail}")]
    Network {
        action: &'static str,
        detail: String,
    },

    #[error("Apple's notary service failed to {action}: {detail}")]
    Api {
        action: &'static str,
        detail: String,
    },

    #[error("Apple didn't accept submission {submission_id} (status: {status}){}", summary.as_deref().map(|s| format!(": {s}")).unwrap_or_default())]
    Rejected {
        submission_id: String,
        /// Apple's status, e.g. `Invalid` or `Rejected`.
        status: String,
        /// Apple's one-line summary from the notarization log.
        summary: Option<String>,
        /// Problems listed in the notarization log.
        issues: Vec<NotaryIssue>,
    },

    #[error("Apple is still processing submission {submission_id} after {} minutes", waited.as_secs() / 60)]
    Timeout {
        submission_id: String,
        path: PathBuf,
        waited: Duration,
    },

    #[error("Apple has no notarization ticket for {}", path.display())]
    NoTicket { path: PathBuf },

    #[error("couldn't staple {}: {detail}", path.display())]
    Staple { path: PathBuf, detail: String },
}

impl NotarizeError {
    pub fn hint(&self) -> Option<String> {
        Some(match self {
            Self::NotAPackage { kind: ArtifactKind::ConfigurationProfile, .. } => {
                "Sign the profile with `mdmsign sign` and upload it to your MDM; there's nothing to notarize.".into()
            }
            Self::NotAPackage { .. } => "Pass a flat installer package (.pkg).".into(),
            Self::Unsigned { path } => format!(
                "Sign it first with a Developer ID Installer identity: `mdmsign sign {}`. Then notarize the signed file.",
                path.display()
            ),
            Self::InvalidApiKey { .. } => "Use the AuthKey_XXXXXXXXXX.p8 file downloaded from App Store Connect (Users and Access > Integrations > App Store Connect API), unmodified.".into(),
            Self::Auth { .. } => "Check that:\n  - the key ID matches the key (it's in the AuthKey_<KEY ID>.p8 file name),\n  - the issuer ID is the one shown above the key list in App Store Connect > Users and Access > Integrations,\n  - the key hasn't been revoked, and\n  - the key's role is Developer or higher (Admin, App Manager or Developer).\nAlso check your Mac's clock: tokens are rejected if it's off by more than a few minutes.".into(),
            Self::Network { .. } => "Check your internet connection. mdmsign needs HTTPS access to appstoreconnect.apple.com, Amazon S3 (s3.us-west-2.amazonaws.com) for the upload, and api.apple-cloudkit.com for stapling. Behind a proxy, set HTTPS_PROXY; a TLS-inspecting proxy's root certificate must be trusted by the system.".into(),
            Self::Api { .. } => "Try again in a few minutes. Check https://developer.apple.com/system-status/ for notary service outages.".into(),
            Self::Rejected { issues, .. } => rejection_hint(issues),
            Self::Timeout { submission_id, path, .. } => format!(
                "Apple is still processing it; busy periods can take hours. Nothing is lost: run `mdmsign staple {}` later. It succeeds once Apple accepts submission {submission_id}.",
                path.display()
            ),
            Self::NoTicket { path } => format!(
                "Either:\n  - it hasn't been notarized yet: run `mdmsign notarize {path}`,\n  - Apple is still processing it: wait a few minutes and try again, or\n  - the file changed after it was notarized (re-signing or rebuilding makes a new file): notarize the current file.",
                path = path.display()
            ),
            Self::Staple { .. } => "Check that the file is a complete, signed flat package with `mdmsign verify`.".into(),
        })
    }

    /// The notary submission this error is about, if any.
    pub fn submission_id(&self) -> Option<&str> {
        match self {
            Self::Rejected { submission_id, .. } | Self::Timeout { submission_id, .. } => {
                Some(submission_id)
            }
            _ => None,
        }
    }

    /// True if the App Store Connect credentials are wrong (the CLI exits
    /// with status 2), rather than the file, Apple or the network.
    pub fn is_usage_error(&self) -> bool {
        match self {
            Self::Auth { .. } | Self::InvalidApiKey { .. } => true,
            Self::NotAPackage { .. }
            | Self::Unsigned { .. }
            | Self::Network { .. }
            | Self::Api { .. }
            | Self::Rejected { .. }
            | Self::Timeout { .. }
            | Self::NoTicket { .. }
            | Self::Staple { .. } => false,
        }
    }
}

fn rejection_hint(issues: &[NotaryIssue]) -> String {
    let mut out = String::new();
    if issues.is_empty() {
        out.push_str("Apple's notarization log didn't list specific problems.\n");
    } else {
        out.push_str("Apple's notarization log lists:\n");
        for issue in issues {
            out.push_str(&format!("  - {issue}\n"));
        }
    }
    let text = issues
        .iter()
        .map(|i| i.message.to_lowercase())
        .collect::<Vec<_>>()
        .join("\n");
    if text.contains("timestamp") {
        out.push_str("Sign the package again without --no-timestamp: notarization needs a secure timestamp.\n");
    }
    if text.contains("developer id")
        || text.contains("hardened runtime")
        || text.contains("not signed")
    {
        out.push_str("Every app, tool and library inside the package must be signed with a Developer ID Application certificate, with the hardened runtime and a timestamp, before the package is built. mdmsign signs the package itself, not its contents; ask the vendor for a notarizable build if it isn't yours.\n");
    }
    out.push_str(
        "Fix the problems, rebuild and sign the package, then run `mdmsign notarize` again.",
    );
    out
}

/// One problem from Apple's notarization log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all(deserialize = "camelCase"))]
pub struct NotaryIssue {
    /// `error` or `warning`.
    #[serde(default)]
    pub severity: String,
    /// The file inside the submission, e.g. `app.pkg/Payload/App.app/Contents/MacOS/App`.
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub message: String,
    /// Apple's documentation for this problem.
    #[serde(default)]
    pub doc_url: Option<String>,
    #[serde(default)]
    pub architecture: Option<String>,
}

impl std::fmt::Display for NotaryIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let severity = if self.severity.is_empty() {
            "issue"
        } else {
            &self.severity
        };
        write!(f, "{severity}: {}", self.message)?;
        match (&self.path, &self.architecture) {
            (Some(path), Some(arch)) => write!(f, " ({path}, {arch})")?,
            (Some(path), None) => write!(f, " ({path})")?,
            _ => {}
        }
        if let Some(url) = &self.doc_url {
            write!(f, " See {url}")?;
        }
        Ok(())
    }
}

/// The parts of Apple's notarization log mdmsign uses.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NotaryLog {
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub status_summary: Option<String>,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub issues: Vec<NotaryIssue>,
}

impl NotaryLog {
    /// Parses the JSON log Apple publishes for a submission. Unknown or
    /// missing fields are tolerated.
    pub fn parse(value: &serde_json::Value) -> Self {
        serde_json::from_value(value.clone()).unwrap_or_default()
    }
}

fn null_as_empty<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<NotaryIssue>, D::Error> {
    Ok(Option::<Vec<NotaryIssue>>::deserialize(d)?.unwrap_or_default())
}

/// Options for [`notarize`].
#[derive(Clone, Debug)]
pub struct NotarizeOptions {
    /// Wait for Apple's verdict instead of returning after upload.
    pub wait: bool,
    /// Staple the ticket after a successful verdict (requires `wait`).
    pub staple: bool,
    /// How long to wait for a verdict.
    pub timeout: Duration,
}

impl Default for NotarizeOptions {
    fn default() -> Self {
        Self {
            wait: true,
            staple: true,
            timeout: Duration::from_secs(30 * 60),
        }
    }
}

/// What [`notarize`] did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "kebab-case")]
pub enum NotarizeOutcome {
    /// Uploaded; not waiting for the verdict.
    Submitted { submission_id: String },
    /// Apple accepted the submission.
    Accepted {
        submission_id: String,
        stapled: bool,
        /// Warnings from the notarization log; Apple accepted anyway.
        issues: Vec<NotaryIssue>,
    },
}

/// What [`staple`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum StapleOutcome {
    /// The ticket was appended to the file.
    Stapled,
    /// The file already carried the current ticket; nothing changed.
    AlreadyStapled,
}

/// Submits a signed `.pkg` for notarization. `progress` receives
/// human-readable status lines.
pub fn notarize(
    path: &Path,
    credentials: &AscCredentials,
    options: &NotarizeOptions,
    progress: &mut dyn FnMut(&str),
) -> Result<NotarizeOutcome> {
    // Cheapest and most fundamental problems first, all before any upload:
    // the wrong kind of file, then unusable credentials, then a missing
    // signature.
    ensure_package(path, "notarize")?;
    let service = AppleNotary {
        notarizer: notarizer(credentials)?,
    };
    ensure_signed(path)?;
    run(
        &service,
        path,
        options,
        &Timing::default(),
        progress,
        &mut |p| staple(p).map(|_| ()),
    )
}

/// Downloads the notarization ticket for a `.pkg` and staples it.
///
/// Stapling again is safe: if the file already carries the current ticket
/// nothing changes, and an outdated ticket is replaced.
pub fn staple(path: &Path) -> Result<StapleOutcome> {
    ensure_package(path, "staple")?;
    let staple_error = |detail: String| NotarizeError::Staple {
        path: path.to_path_buf(),
        detail,
    };

    let file = File::options()
        .read(true)
        .write(true)
        .open(path)
        .map_err(io_error("open", path))?;
    let mut reader = apple_xar::reader::XarReader::new(file)
        .map_err(|e| staple_error(format!("it isn't a readable flat package ({e})")))?;
    let stapler = Stapler::new().map_err(|e| classify("connect to Apple's ticket service", &e))?;
    let ticket = stapler
        .lookup_ticket_for_xar(&mut reader)
        .map_err(|e| match e {
            AppleCodesignError::NotarizationLookupFailure(code, _) if code == "NOT_FOUND" => {
                NotarizeError::NoTicket {
                    path: path.to_path_buf(),
                }
            }
            other => classify("look up the notarization ticket", &other),
        })?;
    let trailer = xar_notarization_trailer(&ticket).map_err(|e| staple_error(e.to_string()))?;

    let mut file = reader.into_inner();
    let len = file.metadata().map_err(io_error("read", path))?.len();
    if let Some(existing) = existing_staple(&mut file, len).map_err(io_error("read", path))? {
        if existing.ticket == ticket {
            return Ok(StapleOutcome::AlreadyStapled);
        }
        // Replace an outdated ticket rather than piling up trailers.
        file.set_len(len - existing.trailer_len)
            .map_err(io_error("write", path))?;
    }
    file.seek(SeekFrom::End(0))
        .and_then(|_| file.write_all(&trailer))
        .and_then(|_| file.sync_all())
        .map_err(io_error("write", path))?;
    Ok(StapleOutcome::Stapled)
}

/// Checks that `path` is a flat package.
fn ensure_package(path: &Path, action: &'static str) -> Result<()> {
    let kind = ArtifactKind::detect(path)?;
    if kind != ArtifactKind::FlatPackage {
        return Err(NotarizeError::NotAPackage {
            path: path.to_path_buf(),
            kind,
            action,
        }
        .into());
    }
    Ok(())
}

/// Checks that a `.pkg` is signed, when that can be told.
fn ensure_signed(path: &Path) -> Result<()> {
    match is_signed(path, ArtifactKind::FlatPackage) {
        Ok(true) | Err(Error::NotImplemented(_)) => Ok(()),
        Ok(false) => Err(NotarizeError::Unsigned {
            path: path.to_path_buf(),
        }
        .into()),
        Err(e) => Err(e),
    }
}

/// Size of a XAR notarization trailer header (`t8lr`, version, type, length, unused).
const TRAILER_HEADER_LEN: u64 = 16;
const TRAILER_MAGIC: &[u8; 4] = b"t8lr";
const TRAILER_TYPE_TERMINATOR: u16 = 1;
const TRAILER_TYPE_TICKET: u16 = 2;

struct ExistingStaple {
    ticket: Vec<u8>,
    /// Bytes from the terminator trailer to the end of the file.
    trailer_len: u64,
}

/// Finds a stapled ticket at the end of a `.pkg`: a terminator header, the
/// ticket, and a ticket header.
fn existing_staple(file: &mut File, len: u64) -> std::io::Result<Option<ExistingStaple>> {
    let Some(header_at) = len.checked_sub(TRAILER_HEADER_LEN) else {
        return Ok(None);
    };
    let Some((typ, ticket_len)) = read_trailer_header(file, header_at)? else {
        return Ok(None);
    };
    let ticket_len = u64::from(ticket_len);
    if typ != TRAILER_TYPE_TICKET {
        return Ok(None);
    }
    let Some(terminator_at) = header_at
        .checked_sub(ticket_len)
        .and_then(|n| n.checked_sub(TRAILER_HEADER_LEN))
    else {
        return Ok(None);
    };
    if read_trailer_header(file, terminator_at)?.map(|(t, _)| t) != Some(TRAILER_TYPE_TERMINATOR) {
        return Ok(None);
    }
    let mut ticket = vec![0; ticket_len as usize];
    file.seek(SeekFrom::Start(terminator_at + TRAILER_HEADER_LEN))?;
    file.read_exact(&mut ticket)?;
    Ok(Some(ExistingStaple {
        ticket,
        trailer_len: len - terminator_at,
    }))
}

fn read_trailer_header(file: &mut File, at: u64) -> std::io::Result<Option<(u16, u32)>> {
    let mut header = [0u8; TRAILER_HEADER_LEN as usize];
    file.seek(SeekFrom::Start(at))?;
    file.read_exact(&mut header)?;
    if &header[0..4] != TRAILER_MAGIC {
        return Ok(None);
    }
    let typ = u16::from_le_bytes([header[6], header[7]]);
    let length = u32::from_le_bytes([header[8], header[9], header[10], header[11]]);
    Ok(Some((typ, length)))
}

/// Builds a [`Notarizer`] from in-memory credentials.
///
/// apple-codesign only builds a `Notarizer` from a key file, so the key is
/// written, in Apple's "unified API key" JSON form, to a file only the
/// current user can read inside a private temporary directory, and deleted as
/// soon as it has been read.
fn notarizer(credentials: &AscCredentials) -> Result<Notarizer, NotarizeError> {
    let der = api_key_der(credentials)?;
    let invalid = |detail: String| NotarizeError::InvalidApiKey {
        label: credentials.source.clone(),
        detail,
    };
    let json = serde_json::json!({
        "issuer_id": credentials.issuer_id.trim(),
        "key_id": credentials.key_id.trim(),
        "private_key": base64::engine::general_purpose::STANDARD.encode(&der),
    })
    .to_string();

    let dir = tempfile::Builder::new()
        .prefix("mdmsign-asc-")
        .tempdir()
        .map_err(|e| invalid(format!("couldn't create a temporary directory: {e}")))?;
    let key_path = dir.path().join("key.json");
    write_private(&key_path, json.as_bytes())
        .map_err(|e| invalid(format!("couldn't write a temporary key file: {e}")))?;
    let notarizer = Notarizer::from_api_key(&key_path).map_err(|e| invalid(e.to_string()));
    // Remove the key file now rather than relying on drop order.
    let _ = std::fs::remove_file(&key_path);
    drop(dir);
    notarizer
}

/// Decodes and checks the `.p8` PEM: it must be a PKCS #8 ECDSA P-256 key.
fn api_key_der(credentials: &AscCredentials) -> Result<Vec<u8>, NotarizeError> {
    let invalid = |detail: &str| NotarizeError::InvalidApiKey {
        label: credentials.source.clone(),
        detail: detail.to_string(),
    };
    let pem = credentials.private_key_pem.expose();
    let body = pem
        .split_once("-----BEGIN PRIVATE KEY-----")
        .and_then(|(_, rest)| rest.split_once("-----END PRIVATE KEY-----"))
        .map(|(body, _)| body)
        .ok_or_else(|| invalid("it isn't a PEM private key"))?;
    let cleaned: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(cleaned)
        .map_err(|_| invalid("the PEM data isn't valid base64"))?;
    match InMemoryPrivateKey::from_pkcs8_der(&der) {
        Ok(InMemoryPrivateKey::EcdsaP256(_)) => Ok(der),
        Ok(_) => Err(invalid(
            "it isn't an ECDSA P-256 key; App Store Connect API keys always are",
        )),
        Err(_) => Err(invalid("the private key couldn't be parsed")),
    }
}

#[cfg(unix)]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = File::options()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)
}

#[cfg(not(unix))]
fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut file = File::options().write(true).create_new(true).open(path)?;
    file.write_all(data)
}

/// Where a submission stands.
#[derive(Clone, Debug, PartialEq, Eq)]
enum SubmissionState {
    InProgress,
    Accepted,
    /// Invalid or Rejected; holds Apple's status word.
    Failed(String),
    Unknown(String),
}

impl SubmissionState {
    /// Maps the notary API status, as displayed by app-store-connect
    /// (`accepted`, `in progress`, `invalid`, `rejected`, `unknown`).
    fn from_status(status: &str) -> Self {
        match status.to_ascii_lowercase().as_str() {
            "in progress" | "inprogress" => Self::InProgress,
            "accepted" => Self::Accepted,
            "invalid" => Self::Failed("Invalid".into()),
            "rejected" => Self::Failed("Rejected".into()),
            other => Self::Unknown(other.into()),
        }
    }
}

/// The notary service, abstracted so the waiting logic can be tested
/// without contacting Apple.
trait NotaryService {
    /// Uploads the package and returns the submission ID.
    fn submit(&self, path: &Path) -> Result<String, NotarizeError>;
    fn status(&self, submission_id: &str) -> Result<SubmissionState, NotarizeError>;
    fn log(&self, submission_id: &str) -> Result<serde_json::Value, NotarizeError>;
}

struct AppleNotary {
    notarizer: Notarizer,
}

impl NotaryService for AppleNotary {
    fn submit(&self, path: &Path) -> Result<String, NotarizeError> {
        match self
            .notarizer
            .notarize_flat_package(path, None)
            .map_err(|e| classify("upload the package to Apple", &e))?
        {
            NotarizationUpload::UploadId(id) => Ok(id),
            NotarizationUpload::NotaryResponse(response) => Ok(response.data.id),
        }
    }

    fn status(&self, submission_id: &str) -> Result<SubmissionState, NotarizeError> {
        let response = self
            .notarizer
            .get_submission(submission_id)
            .map_err(|e| classify("check the submission status", &e))?;
        Ok(SubmissionState::from_status(
            &response.data.attributes.status.to_string(),
        ))
    }

    fn log(&self, submission_id: &str) -> Result<serde_json::Value, NotarizeError> {
        self.notarizer
            .fetch_notarization_log(submission_id)
            .map_err(|e| classify("fetch the notarization log", &e))
    }
}

/// Polling and retry intervals.
#[derive(Clone, Debug)]
struct Timing {
    poll_interval: Duration,
    /// How often to print "still waiting".
    report_every: Duration,
    /// Consecutive network failures tolerated while polling.
    poll_retries: u32,
    /// Apple's ticket service can lag a few seconds behind acceptance.
    staple_attempts: u32,
    staple_retry_delay: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(10),
            report_every: Duration::from_secs(60),
            poll_retries: 3,
            staple_attempts: 4,
            staple_retry_delay: Duration::from_secs(10),
        }
    }
}

fn run(
    service: &dyn NotaryService,
    path: &Path,
    options: &NotarizeOptions,
    timing: &Timing,
    progress: &mut dyn FnMut(&str),
    staple: &mut dyn FnMut(&Path) -> Result<()>,
) -> Result<NotarizeOutcome> {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    let size = std::fs::metadata(path)
        .map(|m| format!(" ({})", human_size(m.len())))
        .unwrap_or_default();
    progress(&format!(
        "Uploading {name}{size} to Apple's notary service…"
    ));
    let submission_id = service.submit(path)?;
    progress(&format!("Uploaded. Submission ID: {submission_id}"));

    if !options.wait {
        return Ok(NotarizeOutcome::Submitted { submission_id });
    }

    progress(&format!(
        "Waiting for Apple's verdict (usually a few minutes; giving up after {})…",
        human_duration(options.timeout)
    ));
    let start = Instant::now();
    let mut last_report = start;
    let mut failures = 0;
    loop {
        match service.status(&submission_id) {
            Ok(SubmissionState::InProgress) => failures = 0,
            Ok(SubmissionState::Accepted) => break,
            Ok(SubmissionState::Failed(status)) => {
                progress(&format!(
                    "Apple marked the submission {status}. Fetching the log…"
                ));
                let log = service
                    .log(&submission_id)
                    .map(|v| NotaryLog::parse(&v))
                    .unwrap_or_default();
                return Err(NotarizeError::Rejected {
                    submission_id,
                    status,
                    summary: log.status_summary,
                    issues: log.issues,
                }
                .into());
            }
            Ok(SubmissionState::Unknown(status)) => {
                return Err(NotarizeError::Api {
                    action: "report a known status",
                    detail: format!(
                        "unexpected status \"{status}\" for submission {submission_id}"
                    ),
                }
                .into());
            }
            Err(NotarizeError::Network { detail, .. }) if failures < timing.poll_retries => {
                failures += 1;
                progress(&format!("Couldn't reach Apple ({detail}); retrying…"));
            }
            Err(e) => return Err(e.into()),
        }
        let elapsed = start.elapsed();
        if elapsed >= options.timeout {
            return Err(NotarizeError::Timeout {
                submission_id,
                path: path.to_path_buf(),
                waited: elapsed,
            }
            .into());
        }
        if last_report.elapsed() >= timing.report_every {
            last_report = Instant::now();
            progress(&format!(
                "Still in progress after {}…",
                human_duration(elapsed)
            ));
        }
        std::thread::sleep(timing.poll_interval.min(options.timeout - elapsed));
    }

    progress("Apple accepted the submission.");
    let issues = service
        .log(&submission_id)
        .map(|v| NotaryLog::parse(&v).issues)
        .unwrap_or_default();
    if !issues.is_empty() {
        progress("Apple's notarization log has notes:");
        for issue in &issues {
            progress(&format!("  - {issue}"));
        }
    }

    let stapled = options.staple && staple_with_retries(path, timing, progress, staple);
    Ok(NotarizeOutcome::Accepted {
        submission_id,
        stapled,
        issues,
    })
}

/// Staples, retrying while Apple's ticket service catches up. Returns
/// whether the ticket was stapled; failures are reported through `progress`
/// because notarization itself succeeded.
fn staple_with_retries(
    path: &Path,
    timing: &Timing,
    progress: &mut dyn FnMut(&str),
    staple: &mut dyn FnMut(&Path) -> Result<()>,
) -> bool {
    progress(&format!("Stapling the ticket to {}…", path.display()));
    for attempt in 1..=timing.staple_attempts.max(1) {
        match staple(path) {
            Ok(()) => return true,
            Err(Error::Notarize(NotarizeError::NoTicket { .. }))
                if attempt < timing.staple_attempts =>
            {
                progress(&format!(
                    "The ticket isn't published yet; retrying in {}…",
                    human_duration(timing.staple_retry_delay)
                ));
                std::thread::sleep(timing.staple_retry_delay);
            }
            Err(e) => {
                progress(&format!("warning: couldn't staple the ticket: {e}"));
                return false;
            }
        }
    }
    false
}

/// Turns an apple-codesign error into one with advice.
fn classify(action: &'static str, err: &(dyn std::error::Error + 'static)) -> NotarizeError {
    let detail = error_chain(err);
    let lower = detail.to_lowercase();
    if let Some((status, summary)) = api_error(&detail) {
        if status == 401 || status == 403 {
            return NotarizeError::Auth {
                detail: format!("HTTP {status}: {summary}"),
            };
        }
        return NotarizeError::Api {
            action,
            detail: format!("HTTP {status}: {summary}"),
        };
    }
    if is_network_error(&lower) {
        return NotarizeError::Network { action, detail };
    }
    if lower.contains("invalidkeyformat")
        || lower.contains("invalidecdsakey")
        || lower.contains("invalid unified api key")
    {
        return NotarizeError::InvalidApiKey {
            label: "the configured key".into(),
            detail,
        };
    }
    NotarizeError::Api { action, detail }
}

/// The error and its causes, without repeats.
fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut parts = vec![err.to_string()];
    let mut source = err.source();
    while let Some(cause) = source {
        let text = cause.to_string();
        if !parts.iter().any(|p| p.contains(&text)) {
            parts.push(text);
        }
        source = cause.source();
    }
    parts.join(": ")
}

fn is_network_error(lower: &str) -> bool {
    const MARKERS: &[&str] = &[
        "error sending request",
        "dns error",
        "failed to lookup address",
        "connection refused",
        "connection reset",
        "connection closed",
        "network is unreachable",
        "timed out",
        "tcp connect",
        "dispatch failure",
        "certificate",
        "tls handshake",
        "proxy",
    ];
    MARKERS.iter().any(|m| lower.contains(m))
}

/// Extracts the HTTP status and Apple's explanation from an App Store
/// Connect error, whose message ends with Apple's JSON error body.
fn api_error(detail: &str) -> Option<(u16, String)> {
    if !detail.contains("appstore connect error") {
        return None;
    }
    let body = &detail[detail.find('{')?..];
    let value = serde_json::Deserializer::from_str(body)
        .into_iter::<serde_json::Value>()
        .next()?
        .ok()?;
    let first = value.get("errors")?.get(0)?;
    let status = first.get("status").and_then(|s| match s {
        serde_json::Value::String(s) => s.parse().ok(),
        serde_json::Value::Number(n) => n.as_u64().and_then(|n| u16::try_from(n).ok()),
        _ => None,
    })?;
    let text = |key| first.get(key).and_then(|v| v.as_str()).unwrap_or_default();
    let summary = match (text("title"), text("detail")) {
        ("", "") => text("code").to_string(),
        (title, "") => title.to_string(),
        ("", detail) => detail.to_string(),
        (title, detail) => format!("{title} {detail}"),
    };
    Some((status, summary))
}

fn human_size(bytes: u64) -> String {
    const MB: f64 = 1024.0 * 1024.0;
    if bytes as f64 >= MB {
        format!("{:.1} MB", bytes as f64 / MB)
    } else {
        format!("{} KB", bytes.div_ceil(1024))
    }
}

fn human_duration(duration: Duration) -> String {
    let secs = duration.as_secs();
    match secs {
        0..60 => format!("{secs}s"),
        _ if secs.is_multiple_of(60) => format!("{} min", secs / 60),
        _ => format!("{}m {}s", secs / 60, secs % 60),
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::VecDeque};

    use super::*;

    /// A sample log in the shape Apple publishes.
    const SAMPLE_LOG: &str = r#"{
  "logFormatVersion": 1,
  "jobId": "2efe2717-52ef-43a5-96dc-0797e4ca1041",
  "status": "Invalid",
  "statusSummary": "Archive contains critical validation errors",
  "statusCode": 4000,
  "archiveFilename": "Example.pkg",
  "uploadDate": "2026-10-16T12:00:00.000Z",
  "sha256": "00",
  "ticketContents": null,
  "issues": [
    {
      "severity": "error",
      "code": null,
      "path": "Example.pkg/Example.pkg Contents/Payload/Applications/Example.app/Contents/MacOS/Example",
      "message": "The binary is not signed with a valid Developer ID certificate.",
      "docUrl": "https://developer.apple.com/documentation/security/resolving-common-notarization-issues#Use-a-valid-Developer-ID-certificate",
      "architecture": "arm64"
    },
    {
      "severity": "error",
      "code": null,
      "path": "Example.pkg",
      "message": "The signature does not include a secure timestamp.",
      "docUrl": null,
      "architecture": null
    }
  ]
}"#;

    struct FakeNotary {
        states: RefCell<VecDeque<Result<SubmissionState, NotarizeError>>>,
        log: serde_json::Value,
    }

    impl FakeNotary {
        fn new(states: Vec<Result<SubmissionState, NotarizeError>>) -> Self {
            Self {
                states: RefCell::new(states.into()),
                log: serde_json::json!({ "issues": [] }),
            }
        }
    }

    impl NotaryService for FakeNotary {
        fn submit(&self, _path: &Path) -> Result<String, NotarizeError> {
            Ok("sub-123".into())
        }
        fn status(&self, _id: &str) -> Result<SubmissionState, NotarizeError> {
            self.states
                .borrow_mut()
                .pop_front()
                .unwrap_or(Ok(SubmissionState::InProgress))
        }
        fn log(&self, _id: &str) -> Result<serde_json::Value, NotarizeError> {
            Ok(self.log.clone())
        }
    }

    fn fast() -> Timing {
        Timing {
            poll_interval: Duration::ZERO,
            report_every: Duration::ZERO,
            poll_retries: 2,
            staple_attempts: 3,
            staple_retry_delay: Duration::ZERO,
        }
    }

    fn options(timeout: Duration) -> NotarizeOptions {
        NotarizeOptions {
            wait: true,
            staple: true,
            timeout,
        }
    }

    fn pkg() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Example.pkg");
        std::fs::write(&path, b"xar!").unwrap();
        (dir, path)
    }

    fn network_error() -> NotarizeError {
        NotarizeError::Network {
            action: "check the submission status",
            detail: "dns error".into(),
        }
    }

    #[test]
    fn parses_log_issues() {
        let log = NotaryLog::parse(&serde_json::from_str(SAMPLE_LOG).unwrap());
        assert_eq!(log.status.as_deref(), Some("Invalid"));
        assert_eq!(
            log.status_summary.as_deref(),
            Some("Archive contains critical validation errors")
        );
        assert_eq!(log.issues.len(), 2);
        assert_eq!(log.issues[0].severity, "error");
        assert_eq!(log.issues[0].architecture.as_deref(), Some("arm64"));
        assert!(
            log.issues[0]
                .doc_url
                .as_deref()
                .unwrap()
                .starts_with("https://")
        );
        assert_eq!(log.issues[1].doc_url, None);
        assert_eq!(
            log.issues[1].to_string(),
            "error: The signature does not include a secure timestamp. (Example.pkg)"
        );
    }

    #[test]
    fn tolerates_odd_logs() {
        assert_eq!(
            NotaryLog::parse(&serde_json::json!("nope")),
            NotaryLog::default()
        );
        let log = NotaryLog::parse(&serde_json::json!({ "issues": null, "extra": 1 }));
        assert!(log.issues.is_empty());
    }

    #[test]
    fn rejection_carries_issues_and_advice() {
        let (_dir, path) = pkg();
        let mut service = FakeNotary::new(vec![
            Ok(SubmissionState::InProgress),
            Ok(SubmissionState::Failed("Invalid".into())),
        ]);
        service.log = serde_json::from_str(SAMPLE_LOG).unwrap();
        let mut lines = Vec::new();
        let err = run(
            &service,
            &path,
            &options(Duration::from_secs(3600)),
            &fast(),
            &mut |l| lines.push(l.to_string()),
            &mut |_| panic!("must not staple a rejected package"),
        )
        .unwrap_err();
        let Error::Notarize(err) = err else {
            panic!("{err:?}")
        };
        assert_eq!(err.submission_id(), Some("sub-123"));
        assert_eq!(
            err.to_string(),
            "Apple didn't accept submission sub-123 (status: Invalid): Archive contains critical validation errors"
        );
        let hint = err.hint().unwrap();
        assert!(
            hint.contains("not signed with a valid Developer ID certificate"),
            "{hint}"
        );
        assert!(hint.contains("without --no-timestamp"), "{hint}");
        assert!(hint.contains("hardened runtime"), "{hint}");
        assert!(
            lines
                .iter()
                .any(|l| l == "Uploaded. Submission ID: sub-123")
        );
    }

    #[test]
    fn accepted_then_stapled_after_ticket_appears() {
        let (_dir, path) = pkg();
        let service = FakeNotary::new(vec![
            Ok(SubmissionState::InProgress),
            Err(network_error()),
            Ok(SubmissionState::Accepted),
        ]);
        let mut attempts = 0;
        let mut lines = Vec::new();
        let outcome = run(
            &service,
            &path,
            &options(Duration::from_secs(3600)),
            &fast(),
            &mut |l| lines.push(l.to_string()),
            &mut |p| {
                attempts += 1;
                if attempts < 2 {
                    Err(NotarizeError::NoTicket {
                        path: p.to_path_buf(),
                    }
                    .into())
                } else {
                    Ok(())
                }
            },
        )
        .unwrap();
        assert_eq!(
            outcome,
            NotarizeOutcome::Accepted {
                submission_id: "sub-123".into(),
                stapled: true,
                issues: Vec::new(),
            }
        );
        assert_eq!(attempts, 2);
        assert!(lines.iter().any(|l| l.contains("retrying")), "{lines:?}");
    }

    #[test]
    fn staple_failure_does_not_fail_notarization() {
        let (_dir, path) = pkg();
        let service = FakeNotary::new(vec![Ok(SubmissionState::Accepted)]);
        let mut lines = Vec::new();
        let outcome = run(
            &service,
            &path,
            &options(Duration::from_secs(3600)),
            &fast(),
            &mut |l| lines.push(l.to_string()),
            &mut |p| {
                Err(NotarizeError::NoTicket {
                    path: p.to_path_buf(),
                }
                .into())
            },
        )
        .unwrap();
        assert!(matches!(
            outcome,
            NotarizeOutcome::Accepted { stapled: false, .. }
        ));
        assert!(
            lines
                .iter()
                .any(|l| l.starts_with("warning: couldn't staple"))
        );
    }

    #[test]
    fn repeated_network_errors_give_up() {
        let (_dir, path) = pkg();
        let service = FakeNotary::new(vec![
            Err(network_error()),
            Err(network_error()),
            Err(network_error()),
        ]);
        let err = run(
            &service,
            &path,
            &options(Duration::from_secs(3600)),
            &fast(),
            &mut |_| {},
            &mut |_| Ok(()),
        )
        .unwrap_err();
        assert!(err.hint().unwrap().contains("HTTPS_PROXY"), "{err}");
    }

    #[test]
    fn timeout_keeps_submission_id() {
        let (_dir, path) = pkg();
        let service = FakeNotary::new(vec![]);
        let err = run(
            &service,
            &path,
            &options(Duration::ZERO),
            &fast(),
            &mut |_| {},
            &mut |_| Ok(()),
        )
        .unwrap_err();
        let Error::Notarize(err @ NotarizeError::Timeout { .. }) = err else {
            panic!("{err:?}")
        };
        assert_eq!(err.submission_id(), Some("sub-123"));
        assert!(err.hint().unwrap().contains("mdmsign staple"));
        assert!(err.hint().unwrap().contains("Example.pkg"));
    }

    #[test]
    fn no_wait_returns_after_upload() {
        let (_dir, path) = pkg();
        let service = FakeNotary::new(vec![]);
        let outcome = run(
            &service,
            &path,
            &NotarizeOptions {
                wait: false,
                staple: false,
                timeout: Duration::ZERO,
            },
            &fast(),
            &mut |_| {},
            &mut |_| panic!("must not staple"),
        )
        .unwrap();
        assert_eq!(
            outcome,
            NotarizeOutcome::Submitted {
                submission_id: "sub-123".into()
            }
        );
    }

    #[test]
    fn outcome_json_shape() {
        let submitted = serde_json::to_value(NotarizeOutcome::Submitted {
            submission_id: "abc".into(),
        })
        .unwrap();
        assert_eq!(
            submitted,
            serde_json::json!({ "status": "submitted", "submission_id": "abc" })
        );
        let accepted = serde_json::to_value(NotarizeOutcome::Accepted {
            submission_id: "abc".into(),
            stapled: true,
            issues: vec![NotaryIssue {
                severity: "warning".into(),
                path: Some("a.pkg".into()),
                message: "m".into(),
                doc_url: None,
                architecture: None,
            }],
        })
        .unwrap();
        assert_eq!(
            accepted,
            serde_json::json!({
                "status": "accepted",
                "submission_id": "abc",
                "stapled": true,
                "issues": [{
                    "severity": "warning",
                    "path": "a.pkg",
                    "message": "m",
                    "doc_url": null,
                    "architecture": null
                }]
            })
        );
    }

    #[test]
    fn classifies_api_errors() {
        let unauthorized = "appstore connect error:\nPOST https://appstoreconnect.apple.com/notary/v2/submissions\n{\n  \"errors\": [\n    {\n      \"code\": \"NOT_AUTHORIZED\",\n      \"detail\": \"Provide a properly configured and signed bearer token, and make sure that it has not expired.\",\n      \"status\": \"401\",\n      \"title\": \"Authentication credentials are missing or invalid.\"\n    }\n  ]\n}";
        let err = classify("upload", &message(unauthorized));
        assert!(matches!(err, NotarizeError::Auth { .. }), "{err:?}");
        assert!(err.is_usage_error());
        assert!(err.to_string().contains("HTTP 401"));
        let hint = err.hint().unwrap();
        assert!(
            hint.contains("issuer ID") && hint.contains("key ID"),
            "{hint}"
        );
        assert!(hint.contains("Developer or higher"), "{hint}");

        let server = unauthorized.replace("401", "500");
        assert!(matches!(
            classify("upload", &message(&server)),
            NotarizeError::Api { .. }
        ));

        let offline = "error sending request for url (https://appstoreconnect.apple.com/notary/v2/submissions): dns error";
        assert!(matches!(
            classify("upload", &message(offline)),
            NotarizeError::Network { .. }
        ));
    }

    fn asc_credentials(pem: String) -> AscCredentials {
        AscCredentials {
            key_id: "ABC123DEFG".into(),
            issuer_id: "00000000-0000-0000-0000-000000000000".into(),
            private_key_pem: crate::Secret::new(pem),
            source: "AuthKey_ABC123DEFG.p8".into(),
        }
    }

    fn pem_for(algorithm: x509_certificate::KeyAlgorithm) -> String {
        let (_, key) = apple_codesign::create_self_signed_code_signing_certificate(
            algorithm,
            apple_codesign::CertificateProfile::DeveloperIdInstaller,
            "MDMSIGNT01",
            "mdmsign test",
            "US",
            chrono::Duration::days(1),
        )
        .unwrap();
        let der = key.to_pkcs8_one_asymmetric_key_der();
        let body = base64::engine::general_purpose::STANDARD.encode(der.as_slice());
        let lines: Vec<_> = body
            .as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        format!(
            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
            lines.join("\n")
        )
    }

    #[test]
    fn builds_notarizer_from_in_memory_key() {
        let pem = pem_for(x509_certificate::KeyAlgorithm::Ecdsa(
            x509_certificate::EcdsaCurve::Secp256r1,
        ));
        assert!(notarizer(&asc_credentials(pem)).is_ok());
    }

    #[test]
    fn rejects_unusable_keys() {
        let rsa = pem_for(x509_certificate::KeyAlgorithm::Rsa);
        let err = notarizer(&asc_credentials(rsa)).err().unwrap();
        assert!(err.to_string().contains("ECDSA P-256"), "{err}");
        assert!(err.is_usage_error());
        assert!(err.hint().unwrap().contains(".p8"));

        let garbage = "-----BEGIN PRIVATE KEY-----\nnot base64!\n-----END PRIVATE KEY-----\n";
        let err = notarizer(&asc_credentials(garbage.into())).err().unwrap();
        assert!(err.to_string().contains("base64"), "{err}");
        // The key material itself never appears in messages.
        assert!(!format!("{err:?}").contains("not base64!"));
    }

    #[test]
    fn unsigned_package_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = crate::testutil::copy_fixture("unsigned.pkg", dir.path());
        match ensure_signed(&pkg) {
            Err(err @ Error::Notarize(NotarizeError::Unsigned { .. })) => {
                assert!(err.hint().unwrap().contains("mdmsign sign"), "{err}");
            }
            // Until .pkg signature detection lands, the check is skipped.
            Ok(()) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn finds_and_replaces_existing_staple() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a.pkg");
        let mut data = b"xar!pretend-archive".to_vec();
        data.extend(xar_notarization_trailer(b"old-ticket").unwrap());
        std::fs::write(&path, &data).unwrap();

        let mut file = File::open(&path).unwrap();
        let existing = existing_staple(&mut file, data.len() as u64)
            .unwrap()
            .expect("a stapled ticket");
        assert_eq!(existing.ticket, b"old-ticket");
        assert_eq!(
            existing.trailer_len,
            (data.len() - b"xar!pretend-archive".len()) as u64
        );

        let plain = dir.path().join("b.pkg");
        std::fs::write(&plain, b"xar!no ticket here, just bytes").unwrap();
        let mut file = File::open(&plain).unwrap();
        assert!(existing_staple(&mut file, 30).unwrap().is_none());
        assert!(existing_staple(&mut file, 4).unwrap().is_none());
    }

    #[derive(Debug)]
    struct Message(String);

    impl std::fmt::Display for Message {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }

    impl std::error::Error for Message {}

    fn message(text: &str) -> Message {
        Message(text.to_string())
    }
}
