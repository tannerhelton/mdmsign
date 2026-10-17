## Summary

<!-- What does this change and why? Link any related issue (e.g. "Fixes #12"). -->

## How was this tested?

<!--
Which tests did you add or run? Did anything need macOS, a real certificate,
the Keychain or Apple's notary service? If you ran `cargo test -- --ignored`,
say which tests and on what OS.
-->

## Checklist

- [ ] `cargo fmt --all --check`
- [ ] `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
- [ ] `cargo test --workspace --all-features --locked`
- [ ] New or changed errors say what went wrong and include a `hint()` (fix)
- [ ] No secrets are printed, logged or passed as process arguments, and none are committed
- [ ] `CHANGELOG.md` updated under **Unreleased** (if users would notice)
- [ ] README updated (if flags, output or behavior changed)
- [ ] No new dependencies, or they're pinned with `=` and explained above
