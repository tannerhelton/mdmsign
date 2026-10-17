# Changelog

All notable changes to mdmsign are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `mdmsign sign` for flat installer packages (`.pkg`) and configuration
  profiles (`.mobileconfig`).
  - Signs with a macOS Keychain identity (by name, unique substring or SHA-1)
    using Apple's `productsign` / `security cms`, or with a `.p12` natively
    using apple-codesign and CMS on macOS and Linux.
  - `--backend auto|native|apple` to choose the implementation.
  - Checks the certificate type before signing. Packages require a
    Developer ID Installer certificate, and choosing a Developer ID
    Application or Mac Installer Distribution certificate fails with a clear
    explanation. Expired certificates and certificates that aren't valid yet
    are refused.
  - Writes `<name>-signed.<ext>` by default, or `-o <path>` / `--in-place`.
    Refuses to overwrite without `--force` and to re-sign without `--resign`.
  - Signs into a temporary file, verifies it, then moves it into place, so a
    failed run never leaves a partial file.
  - Adds a secure timestamp to packages by default (`--no-timestamp`,
    `--timestamp-url`). Profiles are never timestamped.
- `mdmsign pkg` (alias `package`) wraps an installed `.app` in a signed
  package. It refuses unsigned or broken apps, pins the install location
  (not relocatable), upgrades in place with version checks, keeps every file
  in the bundle, and supports `--identifier`, `--version`,
  `--install-location` and an `identifier_prefix` config setting. macOS only.
- `mdmsign notarize` submits signed packages to Apple with an App Store
  Connect API key, waits for the verdict and staples the ticket (`--no-wait`,
  `--no-staple`, `--timeout`, `--json`).
- `mdmsign staple` attaches an existing notarization ticket to a package.
- `mdmsign verify` checks the signature, certificate type, validity, chain,
  timestamp, notarization, staple and (on macOS) Gatekeeper's assessment, and
  gives an MDM-ready verdict with a fix for every problem. Options:
  `--json` with stable check IDs, `--offline`, `--require-notarization` and
  `--no-system-checks`.
- `mdmsign certs` lists Keychain and `.p12` identities and what each can sign
  (`--p12`, `--no-keychain`, `--json`).
- `mdmsign --version` includes the git commit it was built from, e.g.
  `mdmsign 0.1.0 (1a2b3c4d5e)`, so bug reports pin down the exact build.
- Credentials from flags, `MDMSIGN_*` environment variables (including
  `MDMSIGN_P12_BASE64` and `MDMSIGN_ASC_KEY` for CI secrets) or an optional
  config file at `~/.config/mdmsign/config.toml`. The config file refuses to
  hold secrets.
- Supports both the legacy (3DES/SHA-1) and modern (AES/SHA-256) `.p12`
  formats.
- Every error explains what went wrong and how to fix it. Exit status is 0
  on success, 1 on failure or when the file isn't MDM-ready, and 2 for usage
  or credential errors.
- Prebuilt binaries for macOS (Apple silicon, Intel) and Linux (x86_64,
  arm64), a shell installer, and a Homebrew tap (`tannerhelton/tap/mdmsign`).
  Release archives have GitHub build provenance attestations
  (`gh attestation verify`).
  The macOS binaries are signed with a Developer ID Application certificate.
- Building from source with `cargo install` needs Rust 1.94.1 or newer.

[Unreleased]: https://github.com/tannerhelton/mdmsign/commits/main
