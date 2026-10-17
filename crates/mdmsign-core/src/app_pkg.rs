//! Wrapping an installed app bundle (`.app`) in a signed installer package.
//!
//! MDMs deploy apps as `.pkg` installers. [`package_app`] builds one from an
//! app that's already on disk, then signs it with [`crate::sign::sign_file`].
//! The app keeps its vendor's code signature; only the package is signed.
//!
//! The package is built to behave well under an MDM:
//! - The app always installs to the install location (default
//!   `/Applications`). `pkgbuild` normally marks apps as relocatable, which
//!   makes Installer "upgrade" a copy found elsewhere on the disk instead.
//! - Installer checks the bundle ID and version, so an older package can't
//!   downgrade a newer app, and it upgrades the app in place.
//! - Nothing in the bundle is filtered out, because removing files would
//!   break the app's signature.
//!
//! This needs macOS (`pkgbuild`, `codesign`, `ditto`).

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::{
    ArtifactKind, Error, Result, SigningIdentity,
    error::io_error,
    sign::{self, Output, SignOptions, SignOutcome},
    tool,
};

/// Errors building a package from an app.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PackageError {
    #[error("building packages needs macOS (pkgbuild, codesign and ditto)")]
    NeedsMacos,

    #[error("{} isn't an app bundle", .0.display())]
    NotAnApp(PathBuf),

    #[error("couldn't read the app's Info.plist ({}): {detail}", path.display())]
    InfoPlist { path: PathBuf, detail: String },

    #[error("the app's Info.plist has no {key}")]
    MissingKey { key: &'static str },

    #[error("\"{version}\" can't be used as an installer package version")]
    UnsupportedVersion { version: String },

    #[error("\"{identifier}\" isn't a valid package identifier")]
    InvalidIdentifier { identifier: String },

    #[error("{} isn't code signed", .0.display())]
    AppNotSigned(PathBuf),

    #[error("{}'s code signature is invalid: {detail}", path.display())]
    AppSignatureInvalid { path: PathBuf, detail: String },

    #[error("{} changed while it was being copied", .0.display())]
    AppChanged(PathBuf),

    #[error("the install location must be an absolute path, not {}", .0.display())]
    InstallLocation(PathBuf),

    #[error("pkgbuild failed: {detail}")]
    Pkgbuild { detail: String },
}

impl PackageError {
    pub fn hint(&self) -> Option<String> {
        Some(match self {
            Self::NeedsMacos => "Build the package on a Mac, then sign or verify it anywhere.".into(),
            Self::NotAnApp(_) => "Pass the path to an app, e.g. \"/Applications/Example.app\". To sign an existing installer, use `mdmsign sign <file>.pkg`.".into(),
            Self::InfoPlist { .. } | Self::MissingKey { .. } => "The app bundle looks damaged or incomplete. Reinstall or update the app, then try again.".into(),
            Self::UnsupportedVersion { .. } => "Installer versions must be dot-separated numbers such as 1.2.3. Pass one with --version.".into(),
            Self::InvalidIdentifier { .. } => "Use reverse-DNS letters, digits, dots and hyphens, e.g. com.example.pkg.myapp.".into(),
            Self::AppNotSigned(_) => "mdmsign only packages apps that are already signed by their developer, because Macs block unsigned apps. Get a signed build from the vendor.".into(),
            Self::AppSignatureInvalid { .. } => "The app was modified after its developer signed it, or it's incomplete. Reinstall or update it from the vendor, then try again.".into(),
            Self::AppChanged(_) => "Quit the app (and any updater it runs), then try again.".into(),
            Self::InstallLocation(_) => "Use an absolute folder such as /Applications.".into(),
            Self::Pkgbuild { .. } => "Check there's enough free disk space next to the output file, then try again.".into(),
        })
    }
}

/// Facts read from an app bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AppInfo {
    pub path: PathBuf,
    /// The bundle's file name, e.g. `Example.app`.
    pub name: String,
    pub bundle_id: String,
    /// `CFBundleShortVersionString`, if present.
    pub version: Option<String>,
    /// `CFBundleVersion`, if present.
    pub build: Option<String>,
    /// Architectures of the main executable (e.g. `arm64`, `x86_64`), if known.
    pub architectures: Vec<String>,
}

impl AppInfo {
    /// Reads `Contents/Info.plist` from the bundle at `app`.
    pub fn read(app: &Path) -> Result<Self> {
        let is_app = app
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("app"));
        if !app.exists() {
            return Err(Error::FileNotFound(app.to_path_buf()));
        }
        if !is_app || !app.is_dir() {
            return Err(PackageError::NotAnApp(app.to_path_buf()).into());
        }
        let info_path = app.join("Contents/Info.plist");
        if !info_path.is_file() {
            return Err(PackageError::NotAnApp(app.to_path_buf()).into());
        }
        let info: plist::Dictionary =
            plist::from_file(&info_path).map_err(|e| PackageError::InfoPlist {
                path: info_path.clone(),
                detail: e.to_string(),
            })?;
        let string = |key: &str| {
            info.get(key)
                .and_then(|v| v.as_string())
                .map(str::to_string)
        };

        let bundle_id = string("CFBundleIdentifier").ok_or(PackageError::MissingKey {
            key: "CFBundleIdentifier",
        })?;
        let architectures = string("CFBundleExecutable")
            .map(|exe| app.join("Contents/MacOS").join(exe))
            .and_then(|exe| {
                tool::run(
                    "/usr/bin/lipo",
                    [std::ffi::OsStr::new("-archs"), exe.as_os_str()],
                )
                .ok()
            })
            .map(|out| {
                String::from_utf8_lossy(&out.stdout)
                    .split_whitespace()
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            path: app.to_path_buf(),
            name: app
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default(),
            bundle_id,
            version: string("CFBundleShortVersionString"),
            build: string("CFBundleVersion"),
            architectures,
        })
    }

    /// The name without `.app`.
    pub fn stem(&self) -> &str {
        self.name.strip_suffix(".app").unwrap_or(&self.name)
    }
}

/// Options for [`package_app`].
#[derive(Clone, Debug)]
pub struct PackageOptions {
    /// Package (receipt) identifier. Defaults to [`default_identifier`].
    pub identifier: Option<String>,
    /// Prefix for the default identifier, e.g. `com.example.pkg.`.
    pub identifier_prefix: Option<String>,
    /// Installer version. Defaults to the app's version.
    pub version: Option<String>,
    /// Folder the app installs into.
    pub install_location: PathBuf,
}

impl Default for PackageOptions {
    fn default() -> Self {
        Self {
            identifier: None,
            identifier_prefix: None,
            version: None,
            install_location: PathBuf::from("/Applications"),
        }
    }
}

/// What [`package_app`] built.
#[derive(Clone, Debug, Serialize)]
pub struct PackagedApp {
    pub app: AppInfo,
    pub identifier: String,
    pub version: String,
    /// Where the app ends up on the target Mac.
    pub install_path: PathBuf,
    pub sign: SignOutcome,
}

/// The package identifier used when none is given: the prefix plus the
/// bundle ID, or the bundle ID plus `.pkg` without a prefix. The suffix keeps
/// it distinct from the vendor's own installer receipts.
pub fn default_identifier(bundle_id: &str, prefix: Option<&str>) -> String {
    match prefix {
        Some(prefix) if !prefix.is_empty() => {
            let prefix = prefix.trim_end_matches('.');
            format!("{prefix}.{bundle_id}")
        }
        _ => format!("{bundle_id}.pkg"),
    }
}

/// Turns an app version into one Installer accepts: dot-separated numbers.
/// `1.2.3-45` (common in dev builds) becomes `1.2.3.45`.
pub fn package_version(version: &str) -> Option<String> {
    let version = version.trim();
    let candidate = match version.rsplit_once('-') {
        Some((base, build)) if !build.is_empty() && build.chars().all(|c| c.is_ascii_digit()) => {
            format!("{base}.{build}")
        }
        _ => version.to_string(),
    };
    let valid = !candidate.is_empty()
        && candidate
            .split('.')
            .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()));
    valid.then_some(candidate)
}

/// The default output path: `<Name>-<version>-signed.pkg` in the current
/// directory.
pub fn default_output_path(app: &AppInfo, version: &str) -> PathBuf {
    PathBuf::from(format!("{}-{version}-signed.pkg", app.stem()))
}

fn valid_identifier(id: &str) -> bool {
    !id.is_empty()
        && !id.starts_with('.')
        && !id.ends_with('.')
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

/// Resolves the identifier and version without building anything.
pub fn plan(app: &AppInfo, options: &PackageOptions) -> Result<(String, String)> {
    let identifier = options.identifier.clone().unwrap_or_else(|| {
        default_identifier(&app.bundle_id, options.identifier_prefix.as_deref())
    });
    if !valid_identifier(&identifier) {
        return Err(PackageError::InvalidIdentifier { identifier }.into());
    }
    let requested = options
        .version
        .clone()
        .or_else(|| app.version.clone())
        .ok_or(PackageError::MissingKey {
            key: "CFBundleShortVersionString (pass --version)",
        })?;
    let version = package_version(&requested)
        .ok_or(PackageError::UnsupportedVersion { version: requested })?;
    Ok((identifier, version))
}

/// Builds a package that installs `app`, signs it with `identity`, and
/// writes it to `output` (default: [`default_output_path`]). `progress`
/// receives human-readable status lines.
pub fn package_app(
    app: &Path,
    output: Option<&Path>,
    identity: &SigningIdentity,
    sign_options: &SignOptions,
    options: &PackageOptions,
    progress: &mut dyn FnMut(&str),
) -> Result<PackagedApp> {
    if !cfg!(target_os = "macos") {
        return Err(PackageError::NeedsMacos.into());
    }
    let info = AppInfo::read(app)?;
    let (identifier, version) = plan(&info, options)?;
    if !options.install_location.is_absolute() {
        return Err(PackageError::InstallLocation(options.install_location.clone()).into());
    }
    // Fail fast on the wrong certificate, before copying anything.
    identity.check_for(ArtifactKind::FlatPackage, chrono::Utc::now())?;

    let destination = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_output_path(&info, &version));
    if destination.exists() && !sign_options.force {
        return Err(Error::OutputExists(destination));
    }

    progress("Checking the app's code signature…");
    check_app_signature(app)?;

    let dir = match destination.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let staging = tempfile::Builder::new()
        .prefix(".mdmsign-pkg-")
        .tempdir_in(&dir)
        .map_err(io_error("create a temporary directory in", &dir))?;

    let relative_location = options
        .install_location
        .strip_prefix("/")
        .unwrap_or(&options.install_location);
    let root = staging.path().join("root");
    let parent = root.join(relative_location);
    std::fs::create_dir_all(&parent).map_err(io_error("create", &parent))?;
    let copy = parent.join(&info.name);

    progress("Copying the app…");
    tool::run(
        "/usr/bin/ditto",
        [
            std::ffi::OsStr::new("--noqtn"),
            app.as_os_str(),
            copy.as_os_str(),
        ],
    )?;
    // The app could have been updating itself while we copied it.
    check_app_signature(&copy).map_err(|_| PackageError::AppChanged(app.to_path_buf()))?;

    let components = staging.path().join("components.plist");
    write_component_plist(&components, &relative_location.join(&info.name))?;

    progress("Building the package…");
    let unsigned = staging.path().join(format!("{}.pkg", info.stem()));
    let output = tool::run_unchecked(
        "/usr/bin/pkgbuild",
        [
            std::ffi::OsStr::new("--root"),
            root.as_os_str(),
            "--component-plist".as_ref(),
            components.as_os_str(),
            "--identifier".as_ref(),
            identifier.as_ref(),
            "--version".as_ref(),
            version.as_ref(),
            "--install-location".as_ref(),
            "/".as_ref(),
            "--ownership".as_ref(),
            "recommended".as_ref(),
            // Disable pkgbuild's default filters (.DS_Store, .svn, CVS…):
            // dropping files would break the app's code signature.
            "--filter".as_ref(),
            "^$".as_ref(),
            unsigned.as_os_str(),
        ],
    )?;
    if !output.status.success() {
        return Err(PackageError::Pkgbuild {
            detail: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        }
        .into());
    }

    progress(&format!("Signing with \"{}\"…", identity.common_name()));
    let outcome = sign::sign_file(
        &unsigned,
        &Output::Path(destination),
        identity,
        sign_options,
    )?;

    Ok(PackagedApp {
        install_path: options.install_location.join(&info.name),
        app: info,
        identifier,
        version,
        sign: outcome,
    })
}

/// Runs `codesign --verify --deep --strict` on the app.
pub fn check_app_signature(app: &Path) -> Result<()> {
    let output = tool::run_unchecked(
        "/usr/bin/codesign",
        [
            std::ffi::OsStr::new("--verify"),
            "--deep".as_ref(),
            "--strict".as_ref(),
            app.as_os_str(),
        ],
    )?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if stderr.contains("not signed at all") {
        Err(PackageError::AppNotSigned(app.to_path_buf()).into())
    } else {
        Err(PackageError::AppSignatureInvalid {
            path: app.to_path_buf(),
            detail: stderr,
        }
        .into())
    }
}

fn write_component_plist(path: &Path, root_relative_bundle: &Path) -> Result<()> {
    let mut component = plist::Dictionary::new();
    component.insert("BundleHasStrictIdentifier".into(), true.into());
    component.insert("BundleIsRelocatable".into(), false.into());
    component.insert("BundleIsVersionChecked".into(), true.into());
    component.insert("BundleOverwriteAction".into(), "upgrade".into());
    component.insert(
        "RootRelativeBundlePath".into(),
        root_relative_bundle.to_string_lossy().into_owned().into(),
    );
    plist::Value::Array(vec![component.into()])
        .to_file_xml(path)
        .map_err(|e| Error::Io {
            action: "write",
            path: path.to_path_buf(),
            source: std::io::Error::other(e),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(version: Option<&str>) -> AppInfo {
        AppInfo {
            path: PathBuf::from("/Applications/Example App.app"),
            name: "Example App.app".into(),
            bundle_id: "com.example.app".into(),
            version: version.map(str::to_string),
            build: Some("42".into()),
            architectures: vec!["arm64".into()],
        }
    }

    #[test]
    fn normalizes_versions() {
        assert_eq!(package_version("1.2.3").as_deref(), Some("1.2.3"));
        assert_eq!(package_version("0.1.98-150").as_deref(), Some("0.1.98.150"));
        assert_eq!(package_version(" 7 ").as_deref(), Some("7"));
        assert_eq!(package_version("1.2.3-beta"), None);
        assert_eq!(package_version("1.2.3 (45)"), None);
        assert_eq!(package_version("1..2"), None);
        assert_eq!(package_version(""), None);
    }

    #[test]
    fn default_identifier_keeps_clear_of_vendor_receipts() {
        assert_eq!(
            default_identifier("com.example.app", None),
            "com.example.app.pkg"
        );
        assert_eq!(
            default_identifier("com.example.app", Some("org.acme.pkg.")),
            "org.acme.pkg.com.example.app"
        );
        assert_eq!(
            default_identifier("com.example.app", Some("org.acme.pkg")),
            "org.acme.pkg.com.example.app"
        );
    }

    #[test]
    fn plan_uses_overrides_and_validates() {
        let options = PackageOptions::default();
        assert_eq!(
            plan(&app(Some("2.0")), &options).unwrap(),
            ("com.example.app.pkg".into(), "2.0".into())
        );

        let overridden = PackageOptions {
            identifier: Some("org.acme.example".into()),
            version: Some("3.1".into()),
            ..PackageOptions::default()
        };
        assert_eq!(
            plan(&app(Some("2.0")), &overridden).unwrap(),
            ("org.acme.example".into(), "3.1".into())
        );

        let err = plan(&app(Some("2.0 beta")), &options).unwrap_err();
        assert!(err.hint().unwrap().contains("--version"), "{err}");
        assert!(plan(&app(None), &options).is_err());

        let bad_id = PackageOptions {
            identifier: Some("has space".into()),
            ..PackageOptions::default()
        };
        assert!(matches!(
            plan(&app(Some("1")), &bad_id),
            Err(Error::Package(PackageError::InvalidIdentifier { .. }))
        ));
    }

    #[test]
    fn default_output_name() {
        assert_eq!(
            default_output_path(&app(Some("1.2")), "1.2"),
            PathBuf::from("Example App-1.2-signed.pkg")
        );
    }

    #[test]
    fn rejects_things_that_are_not_apps() {
        let dir = tempfile::tempdir().unwrap();
        let folder = dir.path().join("Folder.app");
        std::fs::create_dir(&folder).unwrap();
        assert!(matches!(
            AppInfo::read(&folder),
            Err(Error::Package(PackageError::NotAnApp(_)))
        ));
        let plain = dir.path().join("notes.txt");
        std::fs::write(&plain, "hi").unwrap();
        assert!(matches!(
            AppInfo::read(&plain),
            Err(Error::Package(PackageError::NotAnApp(_)))
        ));
        assert!(matches!(
            AppInfo::read(&dir.path().join("Missing.app")),
            Err(Error::FileNotFound(_))
        ));
    }

    #[test]
    fn reads_info_plist() {
        let dir = tempfile::tempdir().unwrap();
        let app = dir.path().join("Thing.app");
        std::fs::create_dir_all(app.join("Contents")).unwrap();
        std::fs::write(
            app.join("Contents/Info.plist"),
            r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>com.example.thing</string>
<key>CFBundleShortVersionString</key><string>4.5.6</string>
<key>CFBundleVersion</key><string>789</string>
</dict></plist>"#,
        )
        .unwrap();
        let info = AppInfo::read(&app).unwrap();
        assert_eq!(info.bundle_id, "com.example.thing");
        assert_eq!(info.version.as_deref(), Some("4.5.6"));
        assert_eq!(info.build.as_deref(), Some("789"));
        assert_eq!(info.stem(), "Thing");
    }
}
