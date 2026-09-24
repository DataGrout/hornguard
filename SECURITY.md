# Security policy

## Supported versions

The latest release. Hornguard is pre-1.0: fixes land on the current version
and there are no backports.

## Verifying a release

Release tags are signed with SSH keys. The keys allowed to sign one are listed
in [`.allowed_signers`](.allowed_signers), one per machine that makes
releases; a retired machine's key is removed from the list, a compromised one
is removed and noted here. To check a tag:

```
git config gpg.ssh.allowedSignersFile .allowed_signers
git tag -v v0.1.0
```

GitHub shows the same check as a Verified badge on the tag and its release.

## Reporting

Hornguard is the admission boundary of a sandbox whose authors are AI agents,
some of them adversarial or acting on injected instructions. A bypass in it is
a vulnerability in every deployment that trusts it, so please do not open a
public issue for one.

Report privately through GitHub's private vulnerability reporting on this
repository (Security → Report a vulnerability). Reports are received and
coordinated by DataGrout, which maintains Hornguard and runs it in production;
a confirmed bypass is fixed in that deployment before the fix and its
regression fixture are published here. Include the exact text of the goal or
clause, the profiles and backend in force, the engine and version, and what you
observed. A fixture in the format described in `fixtures/README.md` is the most
useful form a report can take.

We acknowledge a report within three business days, tell the reporter within
ten business days whether we have reproduced it, and aim to ship a fix within
thirty days of that. Disclosure is coordinated with the reporter; if we cannot
meet these, we say so rather than going quiet.

A confirmed bypass is fixed in the maintainer's production deployment before
the fix and its regression fixture are published here, because a public
fixture describes a hole until the fix is live.

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
