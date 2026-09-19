# Security policy

Draft. Response window and contact channel to be confirmed before first release.

## Reporting

Hornguard is a sandbox. A bypass in it is a vulnerability in every deployment
that trusts it, so please do not open a public issue for one.

Report privately through GitHub's private vulnerability reporting on this
repository (Security → Report a vulnerability). Include the exact text of the
goal or clause, the profiles and backend in force, the engine and version, and
what you observed. A fixture in the format described in `fixtures/README.md` is
the most useful form a report can take.

We acknowledge reports within three business days and aim to ship a fix and a
regression fixture before any public disclosure, coordinated with the reporter.

## What counts

- Any goal or clause admitted under the default profiles that reaches a pinned
  capability class (process, filesystem, streams, loading, foreign, threads,
  network, database mutation, flags and operators, reflection, parsing,
  destructive state).
- Any rewrite that admits a term the unrewritten form would refuse.
- Any author-facing error that leaks engine paths, flag values, module names, or
  platform clause text under `author_errors(minimal)`.
- Reader disagreement: text the Hornguard reader and an engine's reader turn into
  different terms.

Resource exhaustion under a backend with enforcement hooks in force is in scope.
Resource exhaustion under the judge-only `iso` backend is not, by design: that
backend refuses to run.

## Out of scope

- Content of admitted facts (prompt injection carried as inert data).
- Bugs in the engines themselves.
- Configurations that unpin a class. Unpinning is logged as a warning at policy
  load for exactly this reason.
