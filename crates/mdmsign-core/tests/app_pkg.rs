//! Building signed packages from app bundles (`mdmsign pkg`).

use mdmsign_core::{
    CertKind, Error, Secret, SigningIdentity,
    app_pkg::{self, PackageError, PackageOptions},
    sign::SignOptions,
    testutil::{self, TestIdentity},
};

fn identity(kind: CertKind) -> SigningIdentity {
    let test = TestIdentity::generate(kind);
    SigningIdentity::from_p12(&test.p12, &Secret::new(&test.password), "test.p12").unwrap()
}

fn offline() -> SignOptions {
    SignOptions {
        timestamp: false,
        ..SignOptions::default()
    }
}

#[cfg(not(target_os = "macos"))]
#[test]
fn needs_macos() {
    let dir = tempfile::tempdir().unwrap();
    let app = testutil::make_test_app(dir.path(), "Demo", "com.example.demo", "1.0");
    let err = app_pkg::package_app(
        &app,
        Some(&dir.path().join("out.pkg")),
        &identity(CertKind::DeveloperIdInstaller),
        &offline(),
        &PackageOptions::default(),
        &mut |_| {},
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::Package(PackageError::NeedsMacos)),
        "{err:?}"
    );
}

#[cfg(target_os = "macos")]
mod macos {
    use std::{path::Path, process::Command};

    use mdmsign_core::verify::{self, CheckId, Status, VerifyOptions};

    use super::*;

    fn expand(pkg: &Path, dir: &Path) -> String {
        let expanded = dir.join("expanded");
        let status = Command::new("/usr/sbin/pkgutil")
            .arg("--expand")
            .arg(pkg)
            .arg(&expanded)
            .status()
            .unwrap();
        assert!(status.success());
        std::fs::read_to_string(expanded.join("PackageInfo")).unwrap()
    }

    #[test]
    fn packages_signs_and_pins_install_location() {
        let dir = tempfile::tempdir().unwrap();
        let app = testutil::make_test_app(dir.path(), "Demo", "com.example.demo", "1.2.3-45");
        let out = dir.path().join("Demo.pkg");
        let mut lines = Vec::new();
        let packaged = app_pkg::package_app(
            &app,
            Some(&out),
            &identity(CertKind::DeveloperIdInstaller),
            &offline(),
            &PackageOptions::default(),
            &mut |l| lines.push(l.to_string()),
        )
        .unwrap();

        assert_eq!(packaged.identifier, "com.example.demo.pkg");
        assert_eq!(packaged.version, "1.2.3.45");
        assert_eq!(packaged.install_path, Path::new("/Applications/Demo.app"));
        assert_eq!(packaged.sign.output, out);
        assert!(lines.iter().any(|l| l.contains("Building the package")));

        let report = verify::verify_file(&out, &VerifyOptions::post_sign()).unwrap();
        assert_eq!(
            report.check(CheckId::SignatureValid).unwrap().status,
            Status::Pass
        );
        assert_eq!(
            report.check(CheckId::CertificateType).unwrap().status,
            Status::Pass
        );

        let info = expand(&out, dir.path());
        assert!(
            info.contains(r#"identifier="com.example.demo.pkg""#),
            "{info}"
        );
        assert!(info.contains(r#"version="1.2.3.45""#), "{info}");
        assert!(info.contains(r#"install-location="/""#), "{info}");
        // Not relocatable: Installer won't redirect to a copy elsewhere.
        assert!(!info.contains("<relocate>"), "{info}");
        assert!(info.contains(r#"path="./Applications/Demo.app""#), "{info}");

        let payload = Command::new("/usr/sbin/pkgutil")
            .arg("--payload-files")
            .arg(&out)
            .output()
            .unwrap();
        let files = String::from_utf8_lossy(&payload.stdout);
        assert!(
            files.contains("./Applications/Demo.app/Contents/_CodeSignature"),
            "{files}"
        );

        // Staging directories are cleaned up.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".mdmsign"))
            .collect();
        assert!(leftovers.is_empty());
    }

    #[test]
    fn custom_identifier_version_and_location() {
        let dir = tempfile::tempdir().unwrap();
        let app = testutil::make_test_app(dir.path(), "Demo", "com.example.demo", "9.9");
        let out = dir.path().join("Demo.pkg");
        let options = PackageOptions {
            identifier: Some("org.acme.pkg.demo".into()),
            version: Some("2.0".into()),
            install_location: "/Applications/Utilities".into(),
            ..PackageOptions::default()
        };
        let packaged = app_pkg::package_app(
            &app,
            Some(&out),
            &identity(CertKind::DeveloperIdInstaller),
            &offline(),
            &options,
            &mut |_| {},
        )
        .unwrap();
        assert_eq!(
            packaged.install_path,
            Path::new("/Applications/Utilities/Demo.app")
        );
        let info = expand(&out, dir.path());
        assert!(info.contains(r#"identifier="org.acme.pkg.demo""#), "{info}");
        assert!(info.contains(r#"version="2.0""#), "{info}");
        assert!(
            info.contains(r#"path="./Applications/Utilities/Demo.app""#),
            "{info}"
        );
    }

    #[test]
    fn refuses_unsigned_and_modified_apps() {
        let dir = tempfile::tempdir().unwrap();
        let installer = identity(CertKind::DeveloperIdInstaller);

        let unsigned = testutil::make_test_app(dir.path(), "Unsigned", "com.example.u", "1.0");
        std::fs::remove_dir_all(unsigned.join("Contents/_CodeSignature")).unwrap();
        let err = app_pkg::package_app(
            &unsigned,
            Some(&dir.path().join("u.pkg")),
            &installer,
            &offline(),
            &PackageOptions::default(),
            &mut |_| {},
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::Package(PackageError::AppNotSigned(_))),
            "{err:?}"
        );

        let modified = testutil::make_test_app(dir.path(), "Modified", "com.example.m", "1.0");
        std::fs::write(
            modified.join("Contents/MacOS/Modified"),
            "#!/bin/sh\nexit 1\n",
        )
        .unwrap();
        let err = app_pkg::package_app(
            &modified,
            Some(&dir.path().join("m.pkg")),
            &installer,
            &offline(),
            &PackageOptions::default(),
            &mut |_| {},
        )
        .unwrap_err();
        assert!(
            matches!(
                err,
                Error::Package(PackageError::AppSignatureInvalid { .. })
            ),
            "{err:?}"
        );
        assert!(err.hint().unwrap().contains("Reinstall"));
    }

    #[test]
    fn refuses_application_certificate_before_building() {
        let dir = tempfile::tempdir().unwrap();
        let app = testutil::make_test_app(dir.path(), "Demo", "com.example.demo", "1.0");
        let out = dir.path().join("Demo.pkg");
        let err = app_pkg::package_app(
            &app,
            Some(&out),
            &identity(CertKind::DeveloperIdApplication),
            &offline(),
            &PackageOptions::default(),
            &mut |_| {},
        )
        .unwrap_err();
        assert!(err.to_string().contains("Developer ID Installer"), "{err}");
        assert!(!out.exists());
    }

    #[test]
    fn refuses_to_overwrite_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let app = testutil::make_test_app(dir.path(), "Demo", "com.example.demo", "1.0");
        let out = dir.path().join("Demo.pkg");
        std::fs::write(&out, "existing").unwrap();
        let err = app_pkg::package_app(
            &app,
            Some(&out),
            &identity(CertKind::DeveloperIdInstaller),
            &offline(),
            &PackageOptions::default(),
            &mut |_| {},
        )
        .unwrap_err();
        assert!(matches!(err, Error::OutputExists(_)), "{err:?}");
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "existing");
    }
}
