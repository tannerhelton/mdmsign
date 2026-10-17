# Security policy

mdmsign handles signing certificates, private keys and App Store Connect API
keys, so we take security reports seriously.

## Reporting a vulnerability

**Please don't open a public issue.** Report it privately through GitHub
Security Advisories:

**[Report a vulnerability](https://github.com/tannerhelton/mdmsign/security/advisories/new)**
(or go to the repository's **Security** tab and choose **Report a vulnerability**).

Please include:

- what you found and its impact,
- steps to reproduce (a minimal file or command line helps),
- the mdmsign version (`mdmsign --version`) and OS.

**Never include real secrets** (passwords, `.p12` or `.p8` files) in a
report. Use throwaway certificates to reproduce.

You'll get an acknowledgement within a few days. We'll work with you on a fix
and a coordinated disclosure, and credit you in the advisory unless you'd
rather not be named.

Examples of what we consider security issues:

- a password, private key or API key appearing in output, logs, error
  messages, JSON, temporary files or process arguments,
- `mdmsign verify` reporting a file as signed, valid or MDM-ready when it
  isn't,
- signing or writing a file somewhere other than the requested output path,
  or modifying the input without `--in-place`,
- weaknesses in how mdmsign loads `.p12` files, profiles or packages.

## Supported versions

mdmsign is pre-1.0. Security fixes go into the latest release only.

## How mdmsign handles secrets

- **Config files never hold secrets.** mdmsign refuses to load a config file
  with a key that looks like a secret (`password`, `secret`, `private_key`).
  The config can only *name* the environment variable that holds a password
  (`p12_password_env`) or point to a key file (`key_path`).
- **Secrets come from environment variables or a prompt.** `.p12` passwords
  come from `MDMSIGN_P12_PASSWORD` (or the variable named in the config) or an
  interactive prompt that doesn't echo. In CI, `MDMSIGN_P12_BASE64` and
  `MDMSIGN_ASC_KEY` let you pass the `.p12` and `.p8` contents as secrets
  without writing them to the runner's disk yourself.
- **Secrets are redacted in memory.** Passwords and private keys are held in
  a `Secret` type whose debug output is `[redacted]` and which can't be
  displayed or serialized. Error messages never include them, and tests check
  this.
- **Secrets are never passed as command-line arguments** to Apple's tools,
  where other processes could read them.
- **Keychain private keys stay in the Keychain.** With a Keychain identity,
  mdmsign signs through `productsign` / `security cms`, so macOS's Keychain
  access controls apply and the key is never exported.
- **`.p12` keys stay in memory** for the life of the process. mdmsign doesn't
  write them anywhere.
- **Signed output is staged safely.** Signing writes to a fresh temporary
  directory next to the destination and only renames the file into place
  after it verifies.

## Recommendations for users

- Use a dedicated App Store Connect API key with the **Developer** role for
  notarization, and revoke it if it might have leaked.
- Store `.p12` and `.p8` files outside source control. The repository's
  `.gitignore` excludes common signing-material extensions. In GitHub
  Actions, use encrypted secrets, and consider environment protection rules
  for workflows that sign.
- If a Developer ID certificate's private key is exposed, ask the team's
  Account Holder to revoke it at
  [developer.apple.com](https://developer.apple.com/account/resources/certificates)
  and contact Apple Developer Support.
