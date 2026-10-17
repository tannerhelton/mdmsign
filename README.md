# mdmsign

[![CI](https://github.com/tannerhelton/mdmsign/actions/workflows/ci.yml/badge.svg)](https://github.com/tannerhelton/mdmsign/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**Sign, notarize and verify macOS packages and configuration profiles so they're ready to upload to your MDM.**

`mdmsign` is a command-line tool for Mac admins. Give it a `.pkg`, a
`.mobileconfig` or an installed `.app`, and a signing identity, either from
your Keychain or a `.p12` file. It checks that the certificate is the right type for the file, signs it,
optionally notarizes and staples it, and tells you whether the result is
**MDM-ready** for Jamf Pro, Kandji, Intune, Rippling or any other MDM. It
runs on macOS and Linux, so it also works in CI.

```sh
mdmsign sign MyApp.pkg --identity "Developer ID Installer: Example Corp (ABCDE12345)"
mdmsign notarize MyApp-signed.pkg --key ~/keys/AuthKey_ABC123DEFG.p8 --issuer 00000000-0000-0000-0000-000000000000
mdmsign verify MyApp-signed.pkg
```

> [!NOTE]
> mdmsign is pre-release. v0.1.0 hasn't been published yet, and parts of
> signing, verification, `notarize`, `staple` and `certs` are still landing.
> This README describes how v0.1 will behave.

## Contents

- [Why mdmsign](#why-mdmsign)
- [Install](#install)
- [Quick start](#quick-start): [sign](#sign), [pkg](#pkg), [notarize](#notarize), [staple](#staple), [verify](#verify), [certs](#certs)
- [Credentials](#credentials)
- [Configuration](#configuration)
- [Certificates: which one signs what](#certificates-which-one-signs-what)
- [How signing works](#how-signing-works)
- [MDM notes](#mdm-notes)
- [Exit codes](#exit-codes)
- [Comparison with other tools](#comparison-with-other-tools)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License and acknowledgements](#license-and-acknowledgements)

## Why mdmsign

Apple gives you `productsign`, `security cms`, `notarytool` and `stapler`.
Each does one step, needs a Mac, and fails with messages written for app
developers. mdmsign wraps the whole job for MDM deployment:

- **Certificate checks before signing.** mdmsign refuses to sign a `.pkg`
  with a Developer ID *Application* certificate, a Mac App Store certificate or
  an expired one, and tells you which certificate you need instead.
- **An "MDM-ready" verdict.** `mdmsign verify` checks the signature,
  certificate type, chain, timestamp, notarization and staple, then prints a
  single PASS or FAIL. The exit code works in scripts and `--json` works in
  pipelines.
- **Errors that tell you what to do.** Every error has a `fix:` line naming
  the flag, environment variable or Apple page you need.
- **Safe by default.** It never overwrites a file without `--force`, never
  re-signs without `--resign`, and never leaves a half-written file behind.
- **CI-friendly.** It can sign with a base64-encoded `.p12` from a CI secret on
  macOS or Linux, with no Keychain set up on the runner.

## Install

> [!IMPORTANT]
> v0.1.0 isn't released yet, so the Homebrew, crates.io and GitHub Releases
> options below don't work yet. Until then, build from source:
>
> ```sh
> cargo install --git https://github.com/tannerhelton/mdmsign --locked mdmsign
> ```

**Homebrew** (macOS and Linux). The formula lives in
[`tannerhelton/homebrew-tap`](https://github.com/tannerhelton/homebrew-tap):

```sh
brew install tannerhelton/tap/mdmsign
```

**Cargo** (needs a [Rust toolchain](https://rustup.rs)):

```sh
cargo install mdmsign --locked
```

**GitHub Releases.** Each [release](https://github.com/tannerhelton/mdmsign/releases)
has a shell installer and prebuilt `.tar.xz` archives (with SHA-256 checksums) for macOS (Apple
silicon and Intel) and Linux (x86_64 and arm64):

```sh
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/tannerhelton/mdmsign/releases/latest/download/mdmsign-installer.sh | sh
```

The installer puts `mdmsign` in `~/.cargo/bin`.

## Quick start

Every command has `--help`. Running `mdmsign --help` also lists the
environment variables mdmsign reads.

### sign

```sh
# A package. Needs a Developer ID Installer certificate.
mdmsign sign MyApp.pkg --identity "Developer ID Installer: Example Corp (ABCDE12345)"

# A configuration profile. Any Apple-issued certificate works.
mdmsign sign WiFi.mobileconfig --p12 ~/certs/signing.p12
```

```text
$ mdmsign sign MyApp.pkg -i "Developer ID Installer: Example Corp"
Looking up the identity in your Keychain…
Signing MyApp.pkg with "Developer ID Installer: Example Corp (ABCDE12345)"
macOS may ask you to allow access to the signing key; choose "Always Allow" to skip this next time.
Adding a secure timestamp (needs an internet connection)…
Signed MyApp-signed.pkg using productsign
Next: `mdmsign notarize MyApp-signed.pkg` (recommended), then `mdmsign verify` before uploading.
```

The file type comes from the file's contents, cross-checked against its
extension. Before signing, mdmsign checks that the certificate fits the file
type and is within its validity dates. After signing, it verifies the result.

| Option | What it does |
| --- | --- |
| *(default output)* | Writes `<name>-signed.<ext>` next to the input, e.g. `MyApp.pkg` → `MyApp-signed.pkg`. The input is never modified. |
| `-o, --output <PATH>` | Writes the signed file to `PATH`. |
| `--in-place` | Replaces the input file with the signed one. Can't be combined with `-o`. |
| `-f, --force` | Overwrites the output file if it already exists. Without it, mdmsign refuses. |
| `--resign` | Replaces an existing signature. Without it, mdmsign refuses to sign an already-signed file. Re-signing a `.pkg` invalidates its notarization, so notarize again afterwards. |
| `-i, --identity <NAME\|SHA1>` | Keychain identity (macOS): its full name, a unique part of it, or its SHA-1 fingerprint. |
| `--p12 <FILE>` | A `.p12` with the certificate and private key. The password comes from `MDMSIGN_P12_PASSWORD` or a prompt. |
| `--backend <auto\|native\|apple>` | Signing implementation. `auto` (the default) uses Apple's tools for Keychain identities and native signing for `.p12` files. See [How signing works](#how-signing-works). |
| `--no-timestamp` | Don't add a secure timestamp to a `.pkg`. Useful offline, but **notarization requires a timestamp**. |
| `--timestamp-url <URL>` | Use a different RFC 3161 timestamp server. The default is Apple's (`http://timestamp.apple.com/ts01`). |

Only packages are timestamped. Profiles are never timestamped because macOS
ignores timestamps on them.

### pkg

Wraps an app that's already installed (e.g. in `/Applications`) in a signed
`.pkg` your MDM can deploy. The app keeps its developer's signature; only the
package is signed, so you need a Developer ID Installer certificate. `pkg`
needs macOS (it uses `pkgbuild`, `codesign` and `ditto`).

```sh
mdmsign pkg "/Applications/Example.app" --identity "Developer ID Installer: Example Corp"
mdmsign notarize Example-2.0.3-signed.pkg    # recommended
mdmsign verify Example-2.0.3-signed.pkg
```

```text
$ mdmsign pkg /Applications/Rectangle.app -i "Developer ID Installer: Example Corp"
Packaging Rectangle.app 2.0.3 (build 110; x86_64, arm64)
  Installs to: /Applications/Rectangle.app
  Package ID:  com.knollsoft.Rectangle.pkg
  Version:     2.0.3
…
Built and signed Rectangle-2.0.3-signed.pkg using productsign
```

What it does:

- Refuses apps that aren't signed or whose signature is broken (`codesign
  --verify --deep --strict`), because Macs block them anyway. It checks the
  copy it packages again, in case the app updated itself mid-copy.
- Installs the app to a fixed location. `pkgbuild` normally marks apps as
  relocatable, which makes Installer "upgrade" a copy it finds elsewhere on
  the disk instead of installing to `/Applications`. mdmsign turns that off.
- Upgrades the app in place and has Installer check bundle versions, so an
  older package won't downgrade a newer app.
- Keeps every file in the bundle (pkgbuild's default filters could break the
  app's signature).
- Packages only the app bundle. Settings, caches and other user data outside
  the bundle aren't included. Apps that need a vendor installer (privileged
  helpers, system extensions, drivers) should use the vendor's package.

| Option | What it does |
| --- | --- |
| *(default output)* | Writes `<Name>-<version>-signed.pkg` in the current directory. |
| `-o, --output <PATH>` | Writes the package to `PATH`. |
| `-f, --force` | Overwrites the output file if it already exists. |
| `--identifier <ID>` | Package (install receipt) identifier. The default is `<bundle-id>.pkg`, or `identifier_prefix` + bundle ID from the config file. **Keep it the same for every version of the app** so MDMs and Installer treat new versions as upgrades. If you've deployed the app before, reuse that package ID. |
| `--version <VERSION>` | Installer version. The default is the app's `CFBundleShortVersionString`. `1.2.3-45` becomes `1.2.3.45`; other formats need `--version`. |
| `--install-location <DIR>` | Folder the app installs into. The default is `/Applications`. |
| `-i`, `--p12`, `--backend`, `--no-timestamp`, `--timestamp-url` | Same as for `sign`. |

Quit the app on target Macs before deploying the package.

### notarize

Notarization applies to packages only. mdmsign uploads the signed `.pkg` to
Apple using an [App Store Connect API key](#app-store-connect-api-key-for-notarization),
waits for Apple's verdict, then staples the ticket to the file.

```sh
mdmsign notarize MyApp-signed.pkg --key ~/keys/AuthKey_ABC123DEFG.p8 --issuer 00000000-0000-0000-0000-000000000000
```

```text
Notarized MyApp-signed.pkg (submission 2b5c…).
Ticket stapled.
```

| Option | What it does |
| --- | --- |
| `--key <FILE>` | The `AuthKey_<KEYID>.p8` file. |
| `--key-id <ID>` | The key ID. If omitted, it's taken from an `AuthKey_<ID>.p8` file name. |
| `--issuer <UUID>` | Your Issuer ID, shown in App Store Connect above the API key list. |
| `--no-wait` | Upload and return immediately with the submission ID. Run `mdmsign staple` once Apple accepts it. This also skips stapling. |
| `--no-staple` | Wait for the verdict but don't staple. |
| `--timeout <MINUTES>` | How long to wait for Apple's verdict (default 30). |
| `--json` | Print the result as JSON: `{"status": "accepted", "submission_id": "…", "stapled": true}`, or `{"status": "submitted", "submission_id": "…"}` with `--no-wait`. |

If Apple rejects the submission, mdmsign exits with status 1 and points you at
the notarization log.

### staple

Attaches an existing notarization ticket to a package so Macs can check it
offline. `mdmsign notarize` does this for you unless you pass `--no-wait` or
`--no-staple`.

```sh
mdmsign staple MyApp-signed.pkg
```

### verify

Checks a `.pkg` or `.mobileconfig` and gives an MDM-ready verdict. Each check
passes, warns, fails or is skipped, and every warning or failure comes with a
fix. A file is **MDM-ready when no check fails**. Warnings are advice.

```text
$ mdmsign verify MyApp-signed.pkg
MyApp-signed.pkg (installer package (.pkg))
  Signed by: Developer ID Installer: Example Corp (ABCDE12345) [Developer ID Installer]
  Expires:   2030-05-01

  PASS  Signature is valid
  PASS  Signed with a Developer ID Installer certificate
  PASS  Certificate chains to Apple's Developer ID root
  PASS  Secure timestamp present
  WARN  Not notarized
        fix: Run `mdmsign notarize MyApp-signed.pkg`.
  SKIP  Staple (not notarized)

Result: PASS: MDM-ready (1 warning)
```

*(The check wording above is illustrative. The layout and the `Result:` line
are exact.)*

| Option | What it does |
| --- | --- |
| `--json` | Print the report as JSON (see below). |
| `--offline` | Skip checks that need the network, such as the online notarization lookup. |
| `--require-notarization` | Treat a missing notarization or staple as a failure instead of a warning. |
| `--no-system-checks` | Skip macOS's own assessment (`spctl` / `pkgutil`). These checks only run on macOS. |

`--json` prints the same report in a stable shape for scripts:

```json
{
  "path": "MyApp-signed.pkg",
  "kind": "flat-package",
  "mdm_ready": true,
  "signer": {
    "common_name": "Developer ID Installer: Example Corp (ABCDE12345)",
    "team_id": "ABCDE12345",
    "cert_kind": "developer-id-installer",
    "issuer": "CN=Developer ID Certification Authority, OU=Apple Certification Authority, O=Apple Inc., C=US",
    "sha1": "3A1F…",
    "sha256": "9C0D…",
    "not_before": "2025-05-01T00:00:00Z",
    "not_after": "2030-05-01T00:00:00Z"
  },
  "checks": [
    { "id": "signature-valid", "status": "pass", "summary": "Signature is valid" },
    { "id": "notarization", "status": "warn", "summary": "Not notarized", "fix": "Run `mdmsign notarize MyApp-signed.pkg`." }
  ]
}
```

- `kind` is `flat-package` or `configuration-profile`.
- `signer` is `null` for unsigned files.
- `status` is `pass`, `warn`, `fail` or `skip`. `detail` and `fix` are left out when empty.
- `cert_kind` is one of `developer-id-installer`, `developer-id-application`,
  `mac-installer-distribution`, `apple-distribution`, `apple-development` or
  `other`.
- Check `id`s are stable: `format`, `signed`, `signature-valid`,
  `certificate-type`, `certificate-validity`, `certificate-chain`,
  `timestamp`, `notarization`, `staple`, `gatekeeper`, `profile-content`. Not
  every check applies to every file type.

```sh
# Gate a pipeline on the verdict:
mdmsign verify --json MyApp-signed.pkg | jq -e '.mdm_ready'
# Or just use the exit code:
mdmsign verify --require-notarization MyApp-signed.pkg && echo "ready to upload"
```

### certs

Lists your signing identities and what each one can sign, so you can pick the
right one before you start.

```sh
mdmsign certs                       # Keychain identities (macOS)
mdmsign certs --p12 signing.p12     # also inspect a .p12
mdmsign certs --no-keychain --p12 signing.p12 --json
```

Each entry shows the name, SHA-1, certificate type, Team ID, expiry date, the
file types it can sign, and notes such as *"can't sign .pkg; you need
Developer ID Installer"*. Use the SHA-1 with `--identity` when two
certificates share a name.

## Credentials

mdmsign resolves credentials in this order: **command-line flags, then
environment variables, then the [config file](#configuration)**. Giving both a
Keychain identity and a `.p12` at the same level is an error.

### Keychain identity (macOS)

If your certificate and its private key are in your login Keychain, pass its
name or SHA-1:

```sh
mdmsign sign MyApp.pkg -i "Developer ID Installer: Example Corp (ABCDE12345)"
mdmsign sign MyApp.pkg -i "developer id installer"      # a unique part of the name works too
mdmsign sign MyApp.pkg -i 3A1F0C...                     # full 40-character SHA-1
```

Run `mdmsign certs` (or `security find-identity -p basic`) to see what's
available. If an expired and a renewed certificate share a name, mdmsign picks
the valid one. The private key never leaves the Keychain: mdmsign signs with
Apple's own tools, and macOS may ask you to allow access the first time.

### Exporting a .p12 from Keychain Access

You need a `.p12` to sign on Linux or in CI, or to use the native backend.

1. Open **Keychain Access** and select the **login** keychain, then **My Certificates**.
2. Find the certificate (e.g. *Developer ID Installer: Example Corp*) and
   expand it to check that its private key is underneath. If there's no key,
   the key is on the Mac that created the certificate request.
3. Select the certificate, then choose **File > Export Items…** and pick
   **Personal Information Exchange (.p12)**.
4. Choose a strong password. You'll provide it to mdmsign as
   `MDMSIGN_P12_PASSWORD`.

Both the format Keychain Access exports (3DES/SHA-1) and the OpenSSL 3
default (AES/SHA-256) are supported. Keep the `.p12` out of version control.
This repository's `.gitignore` already excludes `*.p12`, `*.p8` and similar.

### CI: a .p12 from secrets

Store the `.p12` as base64 so it fits in a CI secret. With the
[GitHub CLI](https://cli.github.com):

```sh
base64 -i installer.p12 | gh secret set MDMSIGN_P12_BASE64
gh secret set MDMSIGN_P12_PASSWORD          # paste the .p12 password when prompted
gh secret set MDMSIGN_ASC_KEY < AuthKey_ABC123DEFG.p8
gh secret set MDMSIGN_ASC_KEY_ID --body ABC123DEFG
gh secret set MDMSIGN_ASC_ISSUER_ID --body 00000000-0000-0000-0000-000000000000
```

Then sign, notarize and verify in a workflow. It works on Linux runners too:

```yaml
name: Sign package
on: workflow_dispatch

jobs:
  sign:
    runs-on: ubuntu-latest   # or macos-latest
    steps:
      - uses: actions/checkout@v7
      - name: Install mdmsign
        run: curl --proto '=https' --tlsv1.2 -LsSf https://github.com/tannerhelton/mdmsign/releases/latest/download/mdmsign-installer.sh | sh
      - name: Sign, notarize and verify
        env:
          MDMSIGN_P12_BASE64: ${{ secrets.MDMSIGN_P12_BASE64 }}
          MDMSIGN_P12_PASSWORD: ${{ secrets.MDMSIGN_P12_PASSWORD }}
          MDMSIGN_ASC_KEY: ${{ secrets.MDMSIGN_ASC_KEY }}
          MDMSIGN_ASC_KEY_ID: ${{ secrets.MDMSIGN_ASC_KEY_ID }}
          MDMSIGN_ASC_ISSUER_ID: ${{ secrets.MDMSIGN_ASC_ISSUER_ID }}
        run: |
          mdmsign sign build/MyApp.pkg
          mdmsign notarize build/MyApp-signed.pkg
          mdmsign verify build/MyApp-signed.pkg --require-notarization
      - uses: actions/upload-artifact@v7
        with:
          name: MyApp-signed
          path: build/MyApp-signed.pkg
```

When there's no terminal, mdmsign never prompts. A missing password is an
error that tells you which variable to set.

### App Store Connect API key (for notarization)

1. Sign in to [App Store Connect](https://appstoreconnect.apple.com) and open
   **Users and Access > Integrations > App Store Connect API**. You need
   the Account Holder or Admin role to create keys.
2. Under **Team Keys**, create a key with the **Developer** role. That's
   enough for notarization.
3. **Download the `.p8` file. Apple only lets you download it once.** Keep the
   file name (`AuthKey_<KEYID>.p8`) so mdmsign can read the key ID from it.
4. Note the **Key ID** (in the key list) and the **Issuer ID** (shown above
   the list).

If the key is lost or leaked, revoke it in the same place and create a new one.

### Environment variables

| Variable | Used for |
| --- | --- |
| `MDMSIGN_IDENTITY` | Keychain identity name or SHA-1 (macOS). |
| `MDMSIGN_P12_PATH` | Path to a `.p12` signing identity. |
| `MDMSIGN_P12_BASE64` | Base64-encoded `.p12` contents (for CI secrets). Whitespace is ignored. |
| `MDMSIGN_P12_PASSWORD` | Password for the `.p12`. An empty value means an empty password. |
| `MDMSIGN_ASC_KEY_PATH` | Path to the App Store Connect API key (`.p8`). |
| `MDMSIGN_ASC_KEY` | Contents of the `.p8` (for CI secrets). |
| `MDMSIGN_ASC_KEY_ID` | App Store Connect API key ID. |
| `MDMSIGN_ASC_ISSUER_ID` | App Store Connect Issuer ID. |
| `MDMSIGN_CONFIG` | Path to the config file. |

Precedence details:

- **Signing identity:** `--identity` / `--p12`, then `MDMSIGN_IDENTITY` /
  `MDMSIGN_P12_PATH` / `MDMSIGN_P12_BASE64`, then `identity` / `p12_path` in
  the config file. If both `MDMSIGN_P12_PATH` and `MDMSIGN_P12_BASE64` are
  set, the path wins.
- **.p12 password:** `MDMSIGN_P12_PASSWORD`, then the variable named by
  `p12_password_env` in the config file, then a terminal prompt.
- **API key:** `--key`, then `MDMSIGN_ASC_KEY_PATH`, then `MDMSIGN_ASC_KEY`,
  then `key_path` in the config file.
- **Key ID:** `--key-id`, then `MDMSIGN_ASC_KEY_ID`, then `key_id` in the
  config file, then the `AuthKey_<ID>.p8` file name.
- **Issuer ID:** `--issuer`, then `MDMSIGN_ASC_ISSUER_ID`, then `issuer_id`
  in the config file.

## Configuration

The config file is optional. It holds defaults so you don't have to repeat
flags. mdmsign looks for it in this order:

1. `--config <FILE>`
2. `$MDMSIGN_CONFIG`
3. `$XDG_CONFIG_HOME/mdmsign/config.toml`
4. `~/.config/mdmsign/config.toml`

A file named with `--config` or `MDMSIGN_CONFIG` must exist. The default
location is only read if it's there. Unknown keys are rejected, so typos
don't go unnoticed. Paths may start with `~/`.

```toml
[signing]
identity = "Developer ID Installer: Example Corp (ABCDE12345)"  # macOS Keychain
# p12_path = "~/certs/installer.p12"
# p12_password_env = "INSTALLER_P12_PASSWORD"   # name of the env var holding the password
# timestamp = true
# timestamp_url = "http://timestamp.apple.com/ts01"
# backend = "auto"   # auto | native | apple

[notarize]
key_path = "~/.appstoreconnect/AuthKey_ABC123DEFG.p8"
key_id = "ABC123DEFG"
issuer_id = "00000000-0000-0000-0000-000000000000"
# timeout_minutes = 30

[package]   # mdmsign pkg
# identifier_prefix = "com.example.pkg"   # package ID = prefix + app bundle ID
# install_location = "/Applications"
```

> [!WARNING]
> **Never put secrets in the config file.** mdmsign refuses to load a config
> file containing a key that looks like a secret (anything with `password` or
> `secret` in its name, or `private_key`) and exits with status 2. Keep the
> `.p12` password in an environment variable and, if it isn't
> `MDMSIGN_P12_PASSWORD`, name that variable with `p12_password_env`. The
> config file can point to the `.p8` key file with `key_path`, but it never
> contains the key itself.

## Certificates: which one signs what

| Certificate | `.pkg` for MDM | `.mobileconfig` |
| --- | --- | --- |
| **Developer ID Installer** | ✅ The one you want | ✅ |
| Developer ID Application | ❌ Can't sign installer packages | ✅ |
| Mac Installer Distribution (*3rd Party Mac Developer Installer*) | ❌ Mac App Store submissions only; Macs won't trust it for MDM installs | ✅ |
| Apple Distribution / Apple Development | ❌ | ✅ |
| Non-Apple certificate (e.g. your own CA) | ❌ | ⚠️ Signs, but Macs show the profile as "Not Verified" unless the root is trusted |

- **Packages need a Developer ID Installer certificate.** mdmsign checks this
  before signing and explains what to do if you pick the wrong one.
- **Profiles can use any Apple-issued certificate.** Every Apple type chains
  to a root Macs trust, so the profile shows as *Verified*.
- **Only the team's Account Holder can create Developer ID certificates.**
  Ask them to create a Developer ID Installer certificate at
  [developer.apple.com/account/resources/certificates](https://developer.apple.com/account/resources/certificates),
  then install it with its private key (or have them export a `.p12` for you).
- Expired certificates and certificates that aren't valid yet are refused.
  Packages signed with a secure timestamp stay valid after the certificate
  expires.

## How signing works

mdmsign has two signing backends and picks one automatically (`--backend auto`):

| Identity | Backend | `.pkg` | `.mobileconfig` |
| --- | --- | --- | --- |
| `.p12` file or base64 | **native** (in-process, any OS) | [apple-codesign](https://github.com/indygreg/apple-platform-rs) XAR signing | CMS SignedData via `cryptographic-message-syntax` |
| Keychain identity | **apple** (macOS) | `productsign` | `security cms -S` |

**Why two backends?** A Keychain private key stays in the Keychain, and
Keychain access rules decide which apps may use it. Apple's tools are already
trusted to use the key (after you click "Always Allow"). Reading the key out
of the Keychain would mean extra prompts or weaker access rules. A `.p12` key
is already in memory, so mdmsign signs natively, which also works on Linux.
Forcing `--backend native` with a Keychain identity, or `--backend apple` with
a `.p12`, is an error that explains the alternative.

**Every signing run follows the same steps:**

1. Detect the file type and check that the certificate is valid and the right
   type.
2. Refuse to continue if the input is already signed (unless `--resign`) or the
   output exists (unless `--force` or `--in-place`).
3. Sign into a temporary directory next to the destination.
4. Verify the signed file. If verification fails, nothing is written.
5. Move the signed file into place with a single rename.

A failed or interrupted run never leaves a half-written file behind and
never touches the input unless you asked for `--in-place`.

### Platform support

| | macOS | Linux |
| --- | --- | --- |
| Sign with a `.p12` (`.pkg` and `.mobileconfig`) | ✅ | ✅ |
| Sign with a Keychain identity | ✅ | ❌ (no Keychain) |
| `pkg` (build a package from an app) | ✅ | ❌ (needs `pkgbuild`) |
| `notarize` / `staple` | ✅ | ✅ |
| `verify` | ✅ including `spctl` / `pkgutil` system checks | ✅ without system checks |
| `certs` | ✅ Keychain and `.p12` | ✅ `.p12` only |

Windows isn't supported.

## MDM notes

- **Profiles:** Most MDMs accept unsigned profiles, so `mdmsign verify` warns
  about an unsigned profile rather than failing it. Signing proves where the
  profile came from, shows it as *Verified* on the Mac, and stops anyone from
  editing it in transit. Some MDMs strip, replace or add their own signature
  on upload. If that matters to you, check how yours handles signed profiles.
- **Packages:** Notarization isn't required for packages installed by an MDM,
  because MDM installs don't go through Gatekeeper's quarantine check. It is
  still recommended: users can install the same package by hand, and Apple
  scans it for malware. `mdmsign verify` warns about a missing notarization
  unless you pass `--require-notarization`, which makes it a failure.
- **Re-signing a package** invalidates its notarization. Notarize again before
  uploading.

Uploading to common MDMs (menu names change between versions, so check your
MDM's documentation):

- **Jamf Pro:** upload packages under *Settings > Computer management >
  Packages*, and signed profiles under *Computers > Configuration Profiles >
  Upload*.
- **Kandji:** add packages as a *Custom App* Library item and profiles as a
  *Custom Profile* Library item.
- **Microsoft Intune:** add packages as a macOS line-of-business app. Intune
  requires these to be signed with a Developer ID Installer certificate. Add
  profiles with the macOS *Custom* configuration profile template.
- **Rippling:** upload packages and profiles through Rippling's Mac device
  management settings. See Rippling's help center for the current steps.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. For `verify`, the file is MDM-ready (it may still have warnings). |
| `1` | The operation failed, or `verify` found the file isn't MDM-ready. |
| `2` | Usage or credential problem: bad flags, no or wrong signing identity, wrong `.p12` password, wrong certificate type, missing App Store Connect details, or an invalid config file. |

Errors go to stderr as `error: …` followed by `fix: …`.

## Comparison with other tools

**[rcodesign](https://github.com/indygreg/apple-platform-rs/tree/main/apple-codesign)**
is Gregory Szorc's general-purpose, cross-platform reimplementation of Apple
code signing. It signs Mach-O binaries, app bundles, DMGs and packages, and
notarizes and staples them. mdmsign is built on the same `apple-codesign`
library and is deliberately narrower: a workflow layer for Mac admins that adds
configuration profile signing, certificate-type checks, an MDM-ready verdict,
Keychain signing through Apple's tools, and admin-oriented error messages. If
you need to sign apps or binaries, use rcodesign.

| | mdmsign | Apple's tools |
| --- | --- | --- |
| Sign `.pkg` | `mdmsign sign` | `productsign` (macOS, Keychain only) |
| Sign `.mobileconfig` | `mdmsign sign` | `security cms -S` (macOS, Keychain only) |
| Notarize | `mdmsign notarize` | `xcrun notarytool` (macOS) |
| Staple | `mdmsign staple` | `xcrun stapler` (macOS) |
| Verify | `mdmsign verify`: one MDM-ready verdict with fixes | `pkgutil --check-signature`, `spctl --assess`, `security cms -D` |
| Linux / CI without a Mac | ✅ with a `.p12` | ❌ |
| Catches the wrong certificate type | ✅ before signing | ❌ fails or signs something Macs reject |

## Troubleshooting

**"can't sign this installer package (.pkg) with "Developer ID Application: …""**
You picked the wrong certificate type. Packages need a **Developer ID
Installer** certificate, which only the Account Holder can create. Run
`mdmsign certs` to see what you have. See [Certificates](#certificates-which-one-signs-what).

**"the password for identity.p12 is wrong"**
Check `MDMSIGN_P12_PASSWORD` (or the variable named by `p12_password_env`).
It's the password you chose when exporting the `.p12`, not your Mac or Apple
ID password. In CI, make sure the secret has no trailing newline.

**"no password was given for …"**
mdmsign couldn't prompt because there's no terminal (CI, scripts). Set
`MDMSIGN_P12_PASSWORD`.

**"contains a certificate but no private key"**
Export the certificate *together with its private key*. In Keychain Access,
expand the certificate, select it, and export as `.p12`.

**"mdmsign is running as root, so your login Keychain isn't available"**
Don't use `sudo`. Signing doesn't need root, and under `sudo` your login
Keychain isn't searched.

**"no Keychain identity matches …" / "matches more than one Keychain identity"**
The error lists what's available. Use the full name or the SHA-1 from
`mdmsign certs`.

**A Keychain prompt asks to allow access to the key**
That's macOS protecting your private key. Choose **Always Allow** so
`productsign` / `security` can use it without asking next time. For
unattended signing, use a `.p12` instead of the Keychain.

**Timestamp server unreachable / signing hangs at "Adding a secure timestamp"**
Package signing contacts Apple's timestamp server by default. Check your
network, proxy or firewall for `timestamp.apple.com`, or use another server
with `--timestamp-url`. `--no-timestamp` signs offline, but the package can't
be notarized.

**"is already signed"**
Pass `--resign` to replace the signature. For packages, notarize again
afterwards.

**"output file already exists"**
Pass `--force` to overwrite it, `-o` to pick another path, or `--in-place`.

**"missing App Store Connect issuer ID" (or key ID, or API key)**
Pass `--issuer` / `--key-id` / `--key`, set the matching `MDMSIGN_ASC_*`
variable, or add it under `[notarize]` in the config file. See
[App Store Connect API key](#app-store-connect-api-key-for-notarization).

**"config file … contains a secret"**
Remove the secret from the file and use an environment variable. See
[Configuration](#configuration).

**"it's a directory" for a `.pkg`**
That's an old bundle-style package. Rebuild it as a flat package with
`pkgbuild` or `productbuild`.

## Contributing

Bug reports, fixes and new MDM notes are welcome. See
[CONTRIBUTING.md](https://github.com/tannerhelton/mdmsign/blob/main/CONTRIBUTING.md)
for development setup and how tests work. Report security issues privately as
described in [SECURITY.md](https://github.com/tannerhelton/mdmsign/blob/main/SECURITY.md).

## License and acknowledgements

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](https://github.com/tannerhelton/mdmsign/blob/main/LICENSE-APACHE))
- MIT license ([LICENSE-MIT](https://github.com/tannerhelton/mdmsign/blob/main/LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution
intentionally submitted for inclusion in mdmsign by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any additional
terms or conditions.

mdmsign relies on Gregory Szorc's
[apple-platform-rs](https://github.com/indygreg/apple-platform-rs) crates
(`apple-codesign`, `apple-xar`, `cryptographic-message-syntax`,
`x509-certificate`), which are licensed under the
[Mozilla Public License 2.0](https://www.mozilla.org/MPL/2.0/). mdmsign uses
them as unmodified dependencies. Thank you to everyone who has worked out
Apple's signing formats in the open.

mdmsign isn't affiliated with or endorsed by Apple. Apple, macOS and Keychain
are trademarks of Apple Inc.
