# crates/

`hornguard/` is the Rust **client**: it spawns a judge worker and returns
typed verdicts. It is not a second implementation of the judge.

A Rust **port** of the judge and reader is deferred, on purpose, and this note
says why so the decision can be revisited with the same facts.

## What a Rust core was meant to buy

1. **Judging in a position the author's code cannot reach.** In-engine judging
   shares a process with the code it judges; on SWI that is mitigated by the
   protected-static-code flag, on Scryer it is not.
2. **A reader that canonicalises author text** before any engine parses it,
   closing parser differentials between the judge's view and the engine's.
3. **Bindings** for hosts that are not Prolog: a rustler NIF for Elixir, PyO3
   for Python, a C ABI, a Wasm build.
4. **Coverage for engines with no in-engine protections** (Scryer, Trealla).

## What changed

The Prolog judge grew: stratification, floundering, policy files, deferred
needs, classification. A Rust port must track every rule of it, and the
fixture suite makes parity checkable but does not make two implementations
cheaper than one. Meanwhile the first two goals turned out to have a cheaper
path that needs no second implementation:

- **A judge worker.** Run the pack in its own small `swipl` process, separate
  from the engine that runs authors' code, speaking a line protocol over stdio.
  Any host in any language spawns it and gets trusted-position judging. The
  same worker can serve a Scryer or Trealla engine: the judge does not have to
  run on the engine it protects.
- **Canonical re-emission.** The trusted worker reads author text with the
  engine's own reader flags, judges the term, and emits it with
  `write_canonical/1`. Only the canonical form crosses to the untrusted engine,
  so the engine never parses author text and there is no differential to
  exploit. The reader-agreement fixtures then compare the worker's canonical
  form with the target engine's `read_term/2` on the same text, per backend.
- **Wasm without Rust.** SWI-Prolog's 10.x Wasm build runs engines in the
  browser and at the edge. A judge worker compiled that way covers the Wasm
  case for the price of a build step.

Goals 1, 2 and 4 are now met by the worker, and goal 3 is met for Rust by the
client crate, which speaks the worker protocol. What a Rust *core* would
uniquely add is judging in-process for a host that cannot spawn a `swipl` at
all. Nobody has asked for that yet.

## When to build it

- A host wants the judge in-process in a non-Prolog runtime and cannot spawn a
  worker. That is the signal for `hornguard-judge` plus a binding.
- A backend needs a reader that must not depend on SWI being installed at all,
  for example a Scryer-only deployment with strict supply-chain rules. That is
  the signal for `hornguard-reader` on `tree-sitter-prolog`, refusing any tree
  with an error node and re-emitting canonical form.

Until one of those arrives, the next portability work is the judge worker and
canonical re-emission in the pack, not this directory.
