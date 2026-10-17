//! Listing identities from `.p12` files with generated test certificates.
#![cfg(feature = "test-util")]

use mdmsign_core::{
    ArtifactKind, CertKind, Secret, SigningIdentity, certs,
    testutil::{TEAM_ID, TestIdentity},
};

fn load(kind: CertKind) -> SigningIdentity {
    let test = TestIdentity::generate(kind);
    SigningIdentity::from_p12(&test.p12, &Secret::new(&test.password), "identity.p12").unwrap()
}

#[test]
fn json_shape_is_stable() {
    let identity = load(CertKind::DeveloperIdInstaller);
    let entries = certs::list(false, std::slice::from_ref(&identity)).unwrap();
    let json = serde_json::to_value(&entries).unwrap();
    let entry = &json[0];
    let mut keys: Vec<_> = entry.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "can_sign",
            "kind",
            "name",
            "not_after",
            "notes",
            "sha1",
            "source",
            "team_id",
            "usable"
        ]
    );
    assert_eq!(entry["source"], "identity.p12");
    assert_eq!(entry["kind"], "developer-id-installer");
    assert_eq!(entry["team_id"], TEAM_ID);
    assert_eq!(entry["usable"], true);
    assert_eq!(
        entry["can_sign"],
        serde_json::json!(["flat-package", "configuration-profile"])
    );
    assert_eq!(entry["sha1"].as_str().unwrap().len(), 40);
    // RFC 3339 timestamp.
    assert!(entry["not_after"].as_str().unwrap().contains('T'));
}

#[test]
fn wrong_types_get_plain_language_notes() {
    let extra = [
        load(CertKind::DeveloperIdApplication),
        load(CertKind::MacInstallerDistribution),
    ];
    let entries = certs::list(false, &extra).unwrap();

    let app = &entries[0];
    assert_eq!(app.can_sign, [ArtifactKind::ConfigurationProfile]);
    assert!(
        app.notes.iter().any(|n| n
            .contains("Developer ID Application can't sign .pkg; you need Developer ID Installer")),
        "{:?}",
        app.notes
    );

    let mas = &entries[1];
    assert_eq!(mas.kind, CertKind::MacInstallerDistribution);
    assert!(
        mas.notes
            .iter()
            .any(|n| n.contains("Mac Installer Distribution is for the Mac App Store only")),
        "{:?}",
        mas.notes
    );

    assert!(!certs::has_usable_installer(&entries));
    assert!(certs::best_for(&entries, ArtifactKind::FlatPackage).is_none());
    assert!(certs::best_for(&entries, ArtifactKind::ConfigurationProfile).is_some());
    // Identities passed explicitly are never hidden.
    assert!(entries.iter().all(|e| !e.hidden_unless_all()));
}
