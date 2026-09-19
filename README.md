# Hornguard

A default-deny firewall for Prolog programs written by people you don't trust.

Hornguard sits between an untrusted author and a Prolog engine. It reads a goal
or a clause set, judges it against allowlist profiles and a pinned set of
capability classes, and either admits it, admits it subject to needs the host
can satisfy, or refuses it with a reason and a classification. It never
executes what it judges. Every rule is an allow rule. What no profile allows
does not run. A clause set is also judged as a program: it must be stratified,
because a rule set that recurses through negation or aggregation has no single
meaning to be safe about.

The name is Horn clauses plus guard: the condition a clause must pass before its
body runs, applied at the call port to code you did not write.

## Status

**Early.** The judge works: `hornguard_admit/4`, `hornguard_admit_clause/4`,
`hornguard_admit_program/4`, `hornguard_stratification/2`,
`hornguard_floundering/2` and policy files pass the fixture suite, the
generated-term properties, the mutation harness, and the enumeration
differential against SWI's `library(sandbox)`, all under `make test`.
Enforcement, rewrites, the reader and events do not exist yet, so this judges
admission and nothing else. Read [docs/architecture.md](docs/architecture.md)
before relying on it.

## The claim, stated honestly

Prolog lets a capability boundary be drawn where a finite, auditable allowlist
can be complete: terms carry no authority, the only authority is a predicate in
call position, and the places where data becomes an executed goal are a small,
enumerable set. Hornguard does not make Prolog safe. It makes the boundary
explicit, per engine, tested, and hard to weaken by accident. Every admitted
predicate is an attestation. Every meta-predicate missing from the spec table is
a hole. The adversarial suite is the part that matters.

## Layout

| Path | What |
|---|---|
| `docs/architecture.md` | The judge, profiles, pinned classes, policy, semantics checks, testing, API |
| `pack.pl`, `prolog/` | The SWI-Prolog pack (repo root is the pack root) |
| `profiles/` | Allowlist profiles (`iso`, `prologue`, generated `swi*`) and the pinned class table, as Prolog facts |
| `fixtures/verdicts/` | Conformance fixtures: term + profiles + backend, expected verdict and class |
| `fixtures/reader/` | Reader-agreement fixtures (planned) |
| `test/` | plunit suites: fixtures, policy files, generated-term properties, sandbox differential |
| `tools/` | Profile generator, sandbox differential and mutation harness (`make gen-profiles`, `make differential`, `make mutation`) |
| `crates/` | Reserved for the Rust core |

## Backends

| Backend | Judge | Enforcement | Status |
|---|---|---|---|
| `iso` | yes | none (judge-only) | present |
| `swi` | yes | introspection now; native caps, module isolation, `library(sandbox)` second opinion planned | present |
| `scryer` | yes | external, attested by the host | planned |
| `trealla` (Wasm) | yes | runtime fuel and memory | planned |

## License

Apache-2.0. Contributions under the Developer Certificate of Origin; see
[CONTRIBUTING.md](CONTRIBUTING.md). Security reports: see [SECURITY.md](SECURITY.md).
