# Profile reviews

An entry in a profile is an attestation that a predicate is pure under
adversarial use on a given engine. Generation (`make gen-profiles`) produces
the candidate list; a review is a person reading it against the engine it was
generated from. This file is the record. It is not generated.

| Profile(s) | Generated against | Generated | Reviewed by | Reviewed | Notes |
|---|---|---|---|---|---|
| `iso`, `prologue`, `pinned` | hand-written | 2026-09-18 | Nicholas Wright (DataGrout) | 2026-09-22 | ISO builtins less mutation, I/O, loading, flags, reflection; prologue as in the Prolog prologue proposal; pins by name where a single arity would be the whole game |
| `swi`, `swi_lists`, `swi_apply`, `swi_aggregate`, `swi_solution_sequences`, `swi_strings`, `swi_pairs`, `swi_ordsets`, `swi_assoc`, `swi_terms`, `swi_error`, `swi_random`, `swi_backcomp` | SWI-Prolog 9.2.9 | 2026-09-22 | Nicholas Wright (DataGrout) | 2026-09-22 | Read against the sandbox differential (zero unexplained disagreements) and the exclusion table; `swi_random` admits randomness deliberately |
| `engine_scryer`, `engine_trealla` manifests | probe run inside each engine | 2026-09-19 | Nicholas Wright (DataGrout) | 2026-09-22 | Existence only; meta specs on these backends come from the profiles and must be complete |

A regeneration that changes an entry needs a new row, and the differential
(`make test-differential`) is the check that says whether the engine or the
file moved.

## Attested by experiment

`make attest` calls every allowed predicate with tripwires around it
(`tools/attest.pl`). A review reads the list; this runs it.

| Engine | Date | Result | Findings |
|---|---|---|---|
| SWI-Prolog 9.2.9 | 2026-09-22 | 313 pure, 10 declared (`swi_random`), 0 undeclared, 2 skipped (`maplist/6`, `maplist/7` not defined on this engine) | `write_ln/1` writes: pinned. `eval_license/0`, `hash/1`, `index/1` print: excluded from the generated profile. A list in goal position is `consult/1`: pinned under `loading`. |
