# Test fixtures

- `unsigned.pkg`: a tiny unsigned flat package (one text file under
  `/usr/local/share/mdmsign-fixture`). Regenerate with `./make-fixtures.sh` on
  macOS. It contains no signing material.

Signing certificates are never committed; tests generate throwaway
self-signed certificates at run time (see `src/testutil.rs`).
