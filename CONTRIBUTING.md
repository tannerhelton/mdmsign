# Contributing to mdmsign

Thanks for helping. mdmsign is a tool for Mac admins, so the bar for changes
is: does it help someone get a file signed and into their MDM with fewer
surprises? Bug reports, fixes, clearer error messages and MDM-specific notes
are all welcome.

For security problems, don't open an issue. Follow [SECURITY.md](SECURITY.md).

## Development setup

- **Rust:** the latest stable toolchain from [rustup](https://rustup.rs). The
  oldest supported version is `rust-version` in the root `Cargo.toml`
  (currently 1.94.1), and CI checks that it still builds.
- **macOS** is the most complete development platform. The Keychain backend
  and system checks call `productsign`, `security`, `pkgutil` and `spctl`,
  which come with macOS. Install the Xcode Command Line Tools
  (`xcode-select --install`) for `pkgbuild` and friends.
- **Linux** works for everything except the Keychain backend and macOS
  system checks. CI runs on both.

```sh
git clone https://github.com/tannerhelton/mdmsign
cd mdmsign
cargo build
cargo run -- --help
```

## Workspace layout

```text
crates/
  mdmsign-core/      library: all signing, verification and credential logic
    src/
      artifact.rs    detects .pkg vs .mobileconfig from contents + extension
      identity.rs    certificate types and which can sign what
      credentials.rs flags > env > config resolution, .p12 loading
      config.rs      the optional TOML config file (refuses secrets)
      keychain.rs    macOS Keychain identities via `security`
      sign/          Signer trait, backends, safe output handling
      verify/        Report / Check model and per-type verifiers
      notarize.rs    notarization and stapling
      certs.rs       listing identities
      error.rs       Error + hint(), exit-code classification
      secret.rs      Secret: a redacted string for passwords and keys
      tool.rs        running Apple's command-line tools
      testutil.rs    test-only helpers (feature `test-util`)
    tests/fixtures/  unsigned.pkg and the script that regenerates it
  mdmsign/           binary: clap CLI, output formatting, exit codes
```

- `mdmsign-core` uses `thiserror`. Each area has its own error enum, wrapped
  by `mdmsign_core::Error`. It never prints anything.
- `mdmsign` uses `clap` (derive) and `anyhow`. It turns flags into core types,
  prints results, and maps errors to exit codes in `output.rs`.

## Checks (same as CI)

CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) runs these on
`ubuntu-latest` and `macos-latest`. Run them before opening a PR:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
```

`--all-features` turns on `mdmsign-core`'s `test-util` feature, and `--locked`
fails if `Cargo.lock` would change.

CI also runs these. You rarely need them locally unless you touched what
they check:

| Job | What it checks | Run locally |
| --- | --- | --- |
| `msrv` | Builds with the `rust-version` toolchain and default features, the way `cargo install` does | `cargo +1.94.1 check --workspace --locked` |
| `rustdoc` | `mdmsign-core` docs build without warnings | `RUSTDOCFLAGS="-D warnings" cargo doc -p mdmsign-core --no-deps --all-features` |
| `cargo package` | Both crates can be published to crates.io | `cargo package --workspace --locked` |
| `cargo deny` | Known vulnerabilities (RustSec), licenses, duplicate sources ([`deny.toml`](deny.toml)) | `cargo deny check` |
| `zizmor` | Security problems in the workflows and `dependabot.yml` | `zizmor .github/workflows/ci.yml .github/workflows/audit.yml .github/dependabot.yml` |

The advisories check doesn't block PRs, because new advisories appear
without any change here. [`audit.yml`](.github/workflows/audit.yml) runs it
weekly and whenever `Cargo.lock` changes on `main`.

## Testing strategy

- **No secrets in the repository, ever.** Tests generate throwaway
  self-signed certificates at run time with
  `mdmsign_core::testutil::TestIdentity::generate(CertKind::…)`. They carry
  the same Apple extensions as real certificates, so certificate-type checks
  behave the same way. Chain-of-trust checks correctly fail. Each identity is
  exported as a modern (AES/SHA-256) and a legacy (3DES/SHA-1) `.p12`.
- **`test-util` feature.** The helpers live behind
  `#[cfg(any(test, feature = "test-util"))]`. The CLI crate enables the feature
  in its `[dev-dependencies]`. Never enable it in release builds.
- **Fixture package.** `crates/mdmsign-core/tests/fixtures/unsigned.pkg` is a
  tiny unsigned flat package, committed so tests also run on Linux. To
  regenerate it, run `./make-fixtures.sh` in that directory on macOS. It uses
  `pkgbuild`. Use `testutil::copy_fixture` to get a writable copy in a temp
  directory. Don't sign the committed file in place.
- **Sample profile.** `testutil::write_sample_profile` writes a minimal valid
  `.mobileconfig`.
- **macOS-only tests.** Tests that call Apple's tools (`productsign`,
  `security`, `pkgutil`, `spctl`) go behind `#[cfg(target_os = "macos")]`.
  They run on the macOS CI runner and are compiled out on Linux.
- **Real-credential tests.** Tests that need a real Developer ID certificate,
  the Keychain, or Apple's notary service are marked
  `#[ignore = "needs …"]`. They read their inputs from environment variables
  (the same `MDMSIGN_*` variables the CLI uses, unless the ignore reason says
  otherwise) and never run in CI. To run them locally:

  ```sh
  export MDMSIGN_P12_PATH=~/certs/installer.p12 MDMSIGN_P12_PASSWORD=…
  export MDMSIGN_ASC_KEY_PATH=~/keys/AuthKey_ABC123DEFG.p8 MDMSIGN_ASC_ISSUER_ID=…
  cargo test --workspace --all-features -- --ignored
  ```

  Notarization tests upload a real package to Apple.
- **CLI tests** (`crates/mdmsign/tests/cli.rs`) clear every `MDMSIGN_*`
  variable and point `HOME` at a nonexistent directory so your own
  credentials and config can't leak in. Do the same in new CLI tests.
- **Assert that secrets don't leak.** When a test passes a password or key,
  also assert that it doesn't appear in stdout or stderr. See
  `sign_with_wrong_p12_password_fails_clearly`.

## Adding a file type

`ArtifactKind` is deliberately exhaustive, so the compiler points you at every
place a new type must be handled. The steps (also in the crate docs in
`crates/mdmsign-core/src/lib.rs`):

1. Add a variant to `ArtifactKind` in `artifact.rs` and teach
   `ArtifactKind::detect` to recognise it from its contents and extension.
   Give specific advice for near misses.
2. Add a module under `sign/` that implements `sign::Signer` (one per
   backend if both native and Apple-tool signing make sense), and register it
   in `sign::signer_for`. Add signature detection to `sign::is_signed`.
3. Add a module under `verify/` that builds a `Report` from `Check`s, and
   register it in `verify::verify_file`. Reuse existing `CheckId`s where they
   fit. New IDs are part of the `--json` contract, so add them sparingly.
4. Teach `identity::CertKind::suitability` which certificates fit.
5. Add tests using generated identities, update the README (quick start,
   certificate table, platform matrix) and add a CHANGELOG entry.

## Error message guidelines

Admins read these under pressure. Every error must answer two questions:

1. **What went wrong:** the `Display` message (`#[error("…")]`). Lowercase,
   no trailing period, and specific: name the file, certificate or variable,
   e.g. `the password for identity.p12 is wrong`.
2. **What to do about it:** the `hint()` for the error's variant, printed as
   `fix:`. Write full sentences that name the exact flag, environment
   variable, command or Apple page, e.g. `Pass --resign to replace the
   existing signature.`

Also:

- Add new errors to the owning area's enum (e.g. `CredentialError`,
  `PkgError`) and give every variant a hint.
- Problems with how mdmsign was invoked or configured (credentials, config,
  backend choice) exit with status 2. Keep `Error::is_usage_error` in sync.
  Everything else exits with status 1.
- In `verify`, every `Warn` or `Fail` check needs a `fix`.
- **Never print secrets.** Wrap passwords and private keys in `Secret`, which
  redacts `Debug` and has no `Display` or `Serialize`. Only call `expose()`
  where the value is consumed. Never pass secrets to external tools as
  command-line arguments, because other processes can see them (see
  `tool.rs`). Don't include tool output in errors if it might echo a secret.

## Dependency policy

- Every dependency is declared once in the root `Cargo.toml` under
  `[workspace.dependencies]` with an **exact `=` pin**, and crates use
  `dep.workspace = true`. Bump versions deliberately, in their own commit,
  with a CHANGELOG note if behavior changes.
- **The apple-codesign family moves together.** `apple-codesign`,
  `apple-xar`, `cryptographic-message-syntax` and `x509-certificate` (and
  `bcder`) share types, so they must stay on the exact versions
  `apple-codesign` itself depends on. After bumping, check for duplicates with
  `cargo tree -d`, run `cargo deny check` and remove any `deny.toml`
  advisory ignores it reports as no longer needed. A bump can also raise the
  minimum Rust version; if the `msrv` job fails, raise `rust-version`.
- Every ignored advisory in `deny.toml` says why mdmsign isn't affected. Don't
  add one without that reasoning.
- `Cargo.lock` is committed and CI builds with `--locked`.
- Prefer the standard library and existing dependencies over new ones. Explain
  any new dependency in the PR.

## Commits and pull requests

- Keep commits small and logical, with an imperative subject line ("Add
  profile verification", not "added stuff").
- Before opening a PR, run the [checks](#checks-same-as-ci) and update
  `CHANGELOG.md` under **Unreleased** for anything a user would notice.
  Update the README if behavior, flags or output change.
- Fill in the pull request template. Say how you tested, especially anything
  that needed real certificates or a Mac.
- Never commit certificates, `.p12`/`.p8` files or passwords, even expired or
  test ones. `.gitignore` blocks the common extensions. Don't work around it.
- By contributing, you agree that your contributions are dual-licensed under
  MIT OR Apache-2.0, as described in the README.

## Releasing

Releases are built by [dist](https://opensource.axo.dev/cargo-dist/) (formerly
cargo-dist) from `dist-workspace.toml`. Pushing a version tag runs
`.github/workflows/release.yml`, which builds archives for
`aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-gnu`
and `aarch64-unknown-linux-gnu`, creates the GitHub Release with a shell
installer and checksums, and pushes a Homebrew formula to the tap.

**One-time setup:**

1. Create the public tap repository
   [`tannerhelton/homebrew-tap`](https://github.com/tannerhelton/homebrew-tap)
   (an empty repo with a README is enough).
2. Create a fine-grained personal access token with **Contents: read and
   write** on `tannerhelton/homebrew-tap` only.
3. Add it to this repository as an Actions secret named
   **`HOMEBREW_TAP_TOKEN`**. The `publish-homebrew-formula` job uses it.

**Each release:**

1. Move the **Unreleased** entries in `CHANGELOG.md` under a new
   `## [X.Y.Z] - YYYY-MM-DD` heading. dist uses that section as the release
   notes.
2. Bump `version` in `[workspace.package]` and the `mdmsign-core = { …,
   version = "=X.Y.Z" }` pin in `[workspace.dependencies]`, then run
   `cargo build` to update `Cargo.lock`.
3. Run `dist plan` to check what will be built. Merge to `main`.
4. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.
5. After the release workflow succeeds, publish to crates.io (dist doesn't):
   `cargo publish -p mdmsign-core`, then `cargo publish -p mdmsign`.

**Changing the release setup:** edit `dist-workspace.toml`, then run
`dist generate` to regenerate `release.yml`. Don't hand-edit the workflow.
On pull requests the release workflow runs `dist plan`, which fails if the
workflow is out of date. To upgrade dist, install the new version and run
`dist init`.

**macOS code signing.** The macOS binaries are signed with a Developer ID
Application certificate (dist's `macos-sign`). They aren't notarized yet. Set
these Actions secrets before tagging, because a missing secret reaches dist
as an empty value and fails the build rather than skipping signing:

- **`CODESIGN_CERTIFICATE`**: the Developer ID *Application* `.p12`,
  base64-encoded (`base64 -i cert.p12 | pbcopy`). Not the Installer
  certificate, which signs `.pkg` files.
- **`CODESIGN_CERTIFICATE_PASSWORD`**: its password.
- **`CODESIGN_IDENTITY`**: the certificate's name, e.g. `Developer ID
  Application: Example Corp (ABCDE12345)`. `mdmsign certs --p12 cert.p12`
  shows it.

Check a release with `codesign -dv --verbose=2 mdmsign` on the extracted
binary: it should show your Developer ID Application authority.
