# hornguard

A default-deny firewall for untrusted Prolog, for Rust hosts.

Hornguard judges a goal, clause, or clause set before a Prolog engine runs it:
admitted, admitted subject to something the host must supply, or refused with
a reason and a classification. The default is deny, every rule is an allow
rule, and a set of capability classes is pinned shut that no profile can
reopen.

```rust
use hornguard::{Hornguard, Verdict};

let mut hg = Hornguard::builder()
    .profiles(["iso", "prologue"])
    .spawn()?;

match hg.judge_goal("findall(X, member(X, [a, b]), L)")? {
    // Hand `canonical` to the engine, never the author's text.
    Verdict::Admit { canonical } | Verdict::AdmitWith { canonical } => run(&canonical),
    Verdict::AdmitNeeds { needs, .. } => println!("needs {needs:?}"),
    Verdict::Refused { class, rule, .. } => println!("refused: {class} ({rule})"),
}
```

Refusals carry a classification, so a host learns not only that a goal was
stopped but whether it is being probed:

```rust
let v = hg.judge_goal("findall(H, current_prolog_flag(home, H), _)")?;
// Verdict::Refused {
//     class: Class::EscapeAttempt,      // pinned, and hidden inside a meta-argument
//     rule: "pinned(flags_ops)",
//     depth: 1,
//     reason: "permission_error(execute,goal,current_prolog_flag/2)",
// }
```

## How it works

This crate is a client. Judgment happens in a separate SWI-Prolog process, the
*judge worker*, so the judge runs where an author's code cannot reach it. The
crate spawns that process and speaks its line protocol. There is one
implementation of the judge, in Prolog, and this crate is one of the ways to
reach it.

The worker also reads the author's text, under the target backend's reader
flags, and returns admitted terms in operator-free canonical form with the
author's variable names preserved. Hand the engine that, not the original
text, and the engine never parses anything an author wrote.

## Dynamic dispatch

By default an unbound goal in call position is refused. With
`.dynamic_dispatch(true)` on the builder it is rewritten instead, to a call the
judge sees again at the moment it runs, and the verdict is `Verdict::AdmitWith`
carrying the rewritten term as `canonical`. Run that, never the original; the
engine needs the Hornguard pack loaded for `hornguard_call/N` to resolve.

## What this crate does not do

It judges. It never executes Prolog, and it deliberately offers no way to.
Running an admitted goal is the host's job, under the host's engine, with the
host's caps and isolation. Admission is one layer of a safe Prolog host, and
the cheapest one: isolation between authors, time and inference caps, an abort
the author's `catch/3` cannot swallow, and a record of what was admitted and
why are all still yours to build.

## Requirements

SWI-Prolog 9.2 or later on `PATH`, and the Hornguard pack. The crate finds the
pack by, in order: the path given to `Builder::home`, the `HORNGUARD_HOME`
environment variable, then asking `swipl` where the installed pack lives.

```
?- pack_install('https://github.com/DataGrout/hornguard.git').
```

A worker is sequential, so judging takes `&mut self`. A host wanting
parallelism spawns several `Hornguard` values; they share nothing.

## The honest claim

Prolog lets a capability boundary be drawn where a finite, auditable allowlist
can be complete: terms carry no authority, the only authority is a predicate in
call position, and the places where data becomes an executed goal are a small,
enumerable set. Hornguard does not make Prolog safe. It makes the boundary
explicit, per engine, tested, and hard to weaken by accident.

Full documentation, the threat model, and how the judge is tested are in the
[repository](https://github.com/DataGrout/hornguard).

## License

Apache-2.0.
