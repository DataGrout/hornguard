# Fixtures

Fixtures are the contract every implementation of the judge must satisfy. They
are Prolog facts so that both the pack and the Rust core can load them without
a second parser.

## Verdict fixtures (`verdicts/`)

```prolog
verdict(Id, Backend, Profiles, Term, Expected).
```

- `Id`: atom, unique across all files, prefixed by file (`core_unbound_call`).
- `Backend`: `iso` | `swi` | `scryer` | `trealla`. Fixtures under `iso` run on
  every engine in CI.
- `Profiles`: list of profile names in force.
- `Term`: the goal or clause, as a term (not text; reader fixtures cover text).
- `Expected`: `admit` | `admit_with(Rewrites)` | `admit_needs(Profiles)`
  | `refused(Class, Rule)`. `Rule` may carry `depth(N)`.

A fixture that is refused under profiles `P` must also be refused under every
subset of `P` (monotonicity). A rewrite must be admitted under exactly the
profiles the original is admitted under. CI checks both.

## Reader fixtures (`reader/`)

```prolog
reader(Id, Backend, Text, Canonical).
```

`Text` is author input as an atom. `Canonical` is the operator-free canonical
form the Hornguard reader must produce, and the form the backend engine's own
reader must also produce from `Text`. Disagreement is a failing fixture.
`refused(reader(Reason))` in place of `Canonical` marks text the reader must
refuse (quasi-quotations, operator tricks, confusables, pathological depth).

## Detection fixtures

Every `refused(Class, Rule)` fixture is also a detection fixture: a change that
still refuses the term but reclassifies it fails CI. Silent reclassification is
the regression that is otherwise invisible.

## Growing the suite

Every externally reported escape becomes a fixture before its fix lands.
