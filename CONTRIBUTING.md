# Contributing

## Sign-off

Contributions are accepted under the [Developer Certificate of Origin](https://developercertificate.org/).
Add `Signed-off-by: Name <email>` to each commit (`git commit -s`). There is no
CLA and there will not be one: the project cannot be relicensed out from under
its users, and that is a feature.

## Profiles are attestations

An entry in a profile says "this predicate, on this backend, is pure under
adversarial use." Changing a profile therefore requires:

1. A fixture per added or removed indicator, in `fixtures/verdicts/`.
2. For any predicate that takes a goal or closure argument, a `meta_spec/2`
   entry in the same change. A meta-predicate without a spec is refused by the
   judge, so a missing spec shows up as a failing fixture, not a silent hole.
3. Review by a maintainer, and by a second reviewer whenever one is
   available. Hornguard has one maintainer today, so that is not always
   possible; what it never skips is the record. `profiles/REVIEWS.md` says who
   attested which generation of which profile, against which engine, and when.

Pinned classes are not reopened by pull request. Argue for it in an issue first.

## Fixtures are the contract

Every implementation of the judge (today the Prolog pack; a Rust port, if one is
ever built) must pass the same fixture suite. A change to one implementation
that needs a fixture changed is a change to the contract and is reviewed as such.

## What stays out

Host-specific profiles, incident details, tenant data, and anything that names
a particular deployment. Hornguard is the seam; what a host builds above it is
the host's business.
