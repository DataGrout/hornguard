# Releasing

1. Set the version in three places and make them agree: `pack.pl`
   (`version/1`), `crates/hornguard/Cargo.toml`, and a `## VERSION — DATE`
   section at the top of `CHANGELOG.md` that will become the release notes.
2. Commit that on `main` and let CI go green, including the attested job.
3. `tools/tag.sh VERSION`. It refuses on a dirty tree, off `main`, on a
   version mismatch, or on a missing changelog section, runs the suite, and
   makes the tag: signed when `user.signingkey` is configured, annotated
   otherwise. `--quick` runs only the fast suites when CI has just passed on
   the same commit.
4. `git push origin vVERSION`. The `release` workflow verifies the versions
   again, builds `hornguard-VERSION.zip` (the pack and nothing else), takes
   the notes from the changelog section, and publishes the GitHub release.
5. `cargo publish` from `crates/hornguard`, after the tag, so the crate's
   repository link points at something that exists.
6. Check that `pack_install(hornguard)` finds the new version: `pack.pl`
   points at GitHub's per-tag archive, so the tag alone is what it needs.

A patch release is the same six steps. Nothing is pushed by any script.
