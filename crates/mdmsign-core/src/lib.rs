//! Core library for `mdmsign`, an MDM-focused signing tool for Mac admins.
//!
//! It signs flat installer packages (`.pkg`) and configuration profiles
//! (`.mobileconfig`), notarizes and staples packages, and verifies whether a
//! file is ready to upload to an MDM.
//!
//! The heavy lifting is done by [`apple_codesign`] (package signing,
//! notarization, stapling) and [`cryptographic_message_syntax`] (profile
//! signing). On macOS, identities stored in the Keychain are signed with
//! Apple's own tools (`productsign`, `security cms`) so the Keychain's access
//! rules keep working.
//!
//! # Adding a file type
//!
//! 1. Add a variant to [`ArtifactKind`] and teach [`ArtifactKind::detect`] to
//!    recognise it.
//! 2. Add a module under [`sign`] implementing [`sign::Signer`] and register it
//!    in [`sign::signer_for`].
//! 3. Add a module under [`verify`] and register it in [`verify::verify_file`].
//! 4. Teach [`identity::CertKind::suitability`] which certificates fit.

pub mod artifact;
pub mod certs;
pub mod config;
pub mod credentials;
pub mod error;
pub mod identity;
pub mod keychain;
pub mod notarize;
pub mod secret;
pub mod sign;
pub mod tool;
pub mod verify;

#[cfg(any(test, feature = "test-util"))]
pub mod testutil;

pub use artifact::ArtifactKind;
pub use error::{Error, Result};
pub use identity::{CertKind, SigningIdentity};
pub use secret::Secret;
