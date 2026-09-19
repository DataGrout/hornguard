# crates/

Reserved for the Rust core. Planned shape:

- `hornguard-reader`: reads author text with the MIT-licensed
  `tree-sitter-prolog` crate, refuses any tree containing an error node, converts to a term
  against the backend manifest's operator table, and emits operator-free
  canonical form. Reader-agreement fixtures compare its output with each
  engine's own reader.
- `hornguard-judge`: the walk, profiles, pinned classes, meta-spec completion,
  rewrites, classification and events. Must pass `fixtures/verdicts/` exactly
  as the pack does.
- `hornguard-cli`, `hornguard-ffi` (C ABI), `hornguard-nif` (rustler), `hornguard-py`
  (PyO3), `hornguard-wasm`: thin bindings.

The Prolog pack ships first and defines the fixtures the core must match.
