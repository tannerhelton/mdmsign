//! Detecting what kind of file we've been handed.

use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

use serde::Serialize;

use crate::error::{Error, Result, io_error};

/// A kind of file mdmsign can sign and verify.
///
/// See the crate docs for how to add another kind. This enum is deliberately
/// exhaustive so the compiler points at every place a new kind must be
/// handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    /// A flat installer package (`.pkg`): a XAR archive.
    FlatPackage,
    /// A configuration profile (`.mobileconfig`): an XML or binary property
    /// list, optionally wrapped in a CMS (PKCS #7) signature.
    ConfigurationProfile,
}

impl ArtifactKind {
    pub const ALL: &'static [ArtifactKind] = &[Self::FlatPackage, Self::ConfigurationProfile];

    /// The file extension, without the leading dot.
    pub fn extension(self) -> &'static str {
        match self {
            Self::FlatPackage => "pkg",
            Self::ConfigurationProfile => "mobileconfig",
        }
    }

    /// A short human-readable name.
    pub fn description(self) -> &'static str {
        match self {
            Self::FlatPackage => "installer package",
            Self::ConfigurationProfile => "configuration profile",
        }
    }

    /// Guesses the kind from the file extension alone (case-insensitive).
    pub fn from_extension(path: &Path) -> Option<Self> {
        let ext = path.extension()?.to_str()?.to_ascii_lowercase();
        Self::ALL.iter().copied().find(|k| k.extension() == ext)
    }

    /// Detects the kind of file at `path` from its contents, cross-checked
    /// against its extension.
    pub fn detect(path: &Path) -> Result<Self> {
        let metadata = std::fs::metadata(path).map_err(io_error("read", path))?;
        if metadata.is_dir() {
            return Err(unsupported(
                path,
                "it's a directory",
                match path
                    .extension()
                    .map(|e| e.to_string_lossy().to_ascii_lowercase())
                    .as_deref()
                {
                    Some("pkg") => {
                        "This looks like an old bundle-style package. Rebuild it as a flat package with `pkgbuild` or `productbuild`, then sign that."
                    }
                    Some("app") => {
                        "MDMs deploy apps as installer packages. Wrap the app in a signed .pkg with `mdmsign pkg <app>`."
                    }
                    _ => "Pass the path to a .pkg or .mobileconfig file.",
                },
            ));
        }

        let mut head = Vec::with_capacity(512);
        File::open(path)
            .map_err(io_error("read", path))?
            .take(512)
            .read_to_end(&mut head)
            .map_err(io_error("read", path))?;

        let by_ext = Self::from_extension(path);
        match (sniff(&head), by_ext) {
            (Some(Sniffed::Xar), _) => Ok(Self::FlatPackage),
            (Some(Sniffed::Plist | Sniffed::Der), Some(Self::ConfigurationProfile)) => {
                Ok(Self::ConfigurationProfile)
            }
            (Some(Sniffed::Plist | Sniffed::Der), Some(Self::FlatPackage)) => Err(unsupported(
                path,
                "it has a .pkg extension but contains a property list or signature, not an installer package",
                "If this is a configuration profile, rename it to end in .mobileconfig.",
            )),
            (Some(Sniffed::Plist), None) => Err(unsupported(
                path,
                "it's a property list without a .mobileconfig extension",
                "If this is a configuration profile, rename it to end in .mobileconfig.",
            )),
            (Some(Sniffed::Der), None) => Err(unsupported(
                path,
                "it looks like signed data but doesn't have a .mobileconfig extension",
                "If this is a signed configuration profile, rename it to end in .mobileconfig.",
            )),
            (None, Some(Self::FlatPackage)) => Err(unsupported(
                path,
                "it has a .pkg extension but isn't a flat installer package (no XAR header)",
                "Check that the download or build finished. Distribution packages must be built with `productbuild` or `pkgbuild`.",
            )),
            (None, Some(Self::ConfigurationProfile)) => Err(unsupported(
                path,
                "it has a .mobileconfig extension but isn't a property list or signed profile",
                "Open it in a text editor; a profile starts with `<?xml` and contains a `<plist>`.",
            )),
            (None, None) => Err(unsupported(
                path,
                "unrecognised file type",
                "mdmsign handles flat installer packages (.pkg) and configuration profiles (.mobileconfig).",
            )),
        }
    }
}

impl std::fmt::Display for ArtifactKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} (.{})", self.description(), self.extension())
    }
}

fn unsupported(path: &Path, detail: &str, hint: &str) -> Error {
    Error::UnsupportedFile {
        path: PathBuf::from(path),
        detail: detail.to_string(),
        hint: Some(hint.to_string()),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sniffed {
    Xar,
    Plist,
    Der,
}

fn sniff(head: &[u8]) -> Option<Sniffed> {
    if head.starts_with(b"xar!") {
        return Some(Sniffed::Xar);
    }
    if head.starts_with(b"bplist00") {
        return Some(Sniffed::Plist);
    }
    // DER/BER SEQUENCE: CMS ContentInfo starts with 0x30 and a length byte.
    if head.len() >= 2 && head[0] == 0x30 && matches!(head[1], 0x80..=0x84) {
        return Some(Sniffed::Der);
    }
    let text = head.strip_prefix(b"\xEF\xBB\xBF").unwrap_or(head);
    let start = text.iter().position(|b| !b.is_ascii_whitespace())?;
    let text = &text[start..];
    if text.starts_with(b"<?xml")
        || text.starts_with(b"<plist")
        || text.starts_with(b"<!DOCTYPE plist")
    {
        return Some(Sniffed::Plist);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, data: &[u8]) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, data).unwrap();
        path
    }

    #[test]
    fn detects_by_content_and_extension() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = write(dir.path(), "a.pkg", b"xar!\0\x1c\0\x01rest");
        assert_eq!(
            ArtifactKind::detect(&pkg).unwrap(),
            ArtifactKind::FlatPackage
        );

        let xml = write(
            dir.path(),
            "p.mobileconfig",
            b"\n  <?xml version=\"1.0\"?><plist/>",
        );
        assert_eq!(
            ArtifactKind::detect(&xml).unwrap(),
            ArtifactKind::ConfigurationProfile
        );

        let signed = write(dir.path(), "s.MobileConfig", &[0x30, 0x80, 0x06, 0x09]);
        assert_eq!(
            ArtifactKind::detect(&signed).unwrap(),
            ArtifactKind::ConfigurationProfile
        );

        let bom = write(dir.path(), "b.mobileconfig", b"\xEF\xBB\xBF<plist></plist>");
        assert_eq!(
            ArtifactKind::detect(&bom).unwrap(),
            ArtifactKind::ConfigurationProfile
        );
    }

    #[test]
    fn xar_content_wins_over_extension() {
        let dir = tempfile::tempdir().unwrap();
        let pkg = write(dir.path(), "installer.bin", b"xar!\0\x1c");
        assert_eq!(
            ArtifactKind::detect(&pkg).unwrap(),
            ArtifactKind::FlatPackage
        );
    }

    #[test]
    fn rejects_mismatches_with_hints() {
        let dir = tempfile::tempdir().unwrap();
        let fake_pkg = write(dir.path(), "x.pkg", b"PK\x03\x04");
        let err = ArtifactKind::detect(&fake_pkg).unwrap_err();
        assert!(
            err.to_string().contains("isn't a flat installer package"),
            "{err}"
        );
        assert!(err.hint().is_some());

        let plist = write(dir.path(), "x.plist", b"<?xml version=\"1.0\"?>");
        let err = ArtifactKind::detect(&plist).unwrap_err();
        assert!(err.hint().unwrap().contains(".mobileconfig"));
    }

    #[test]
    fn missing_file_and_directory() {
        let dir = tempfile::tempdir().unwrap();
        let err = ArtifactKind::detect(&dir.path().join("nope.pkg")).unwrap_err();
        assert!(matches!(err, Error::FileNotFound(_)), "{err:?}");

        let bundle = dir.path().join("Old.pkg");
        std::fs::create_dir(&bundle).unwrap();
        let err = ArtifactKind::detect(&bundle).unwrap_err();
        assert!(err.hint().unwrap().contains("bundle-style"));

        let app = dir.path().join("Example.app");
        std::fs::create_dir(&app).unwrap();
        let err = ArtifactKind::detect(&app).unwrap_err();
        assert!(err.hint().unwrap().contains("mdmsign pkg"));
    }
}
