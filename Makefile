SWIPL ?= swipl
CARGO ?= cargo

.PHONY: test test-fixtures test-policy test-generated test-worker test-differential test-attest test-attest-engines test-fuzz test-compose test-triage test-crate check differential attest attest-engines fuzz triage gen-profiles manifests mutation worker

test: test-fixtures test-policy test-generated test-worker test-differential test-attest test-attest-engines test-fuzz test-compose test-triage test-crate

## Attestation by experiment: every allowed predicate the engine defines is
## called under several argument shapes with tripwires around output, globals,
## flags, operators, streams, modules, threads, records, dynamic clauses, the
## random state, the working directory and the scratch directory's files. An
## undeclared change fails. See tools/attest.pl.
attest:
	$(SWIPL) -q -g attest -t halt tools/attest.pl

test-attest:
	$(SWIPL) -q -g run_tests -t halt test/test_attest.pl

## The same experiment inside Scryer and Trealla: a probe generated per
## allowed predicate the engine's manifest names, run in that engine with the
## tripwires it can express. Skips an engine that is not on PATH.
attest-engines:
	$(SWIPL) -q -g attest_engines -t halt tools/attest_engine.pl

test-attest-engines:
	$(SWIPL) -q -g run_tests -t halt test/test_attest_engine.pl

## Admit-then-run: seeded terms from allowed, meta, control and pinned
## vocabulary; every one the judge admits is run in the attestation sandbox,
## and a tripwire on an admitted term fails. N and SEED override the defaults.
FUZZ_N ?= 400
FUZZ_SEED ?= 20260922
fuzz:
	$(SWIPL) -q -g "fuzz($(FUZZ_N), $(FUZZ_SEED))" -t halt tools/fuzz.pl

test-fuzz:
	$(SWIPL) -q -g run_tests -t halt test/test_fuzz.pl

## Composition: fixtures the judge admits run inert; judged dispatch through
## the worker, the canonical form and the runtime half; operators end to end.
test-compose:
	$(SWIPL) -q -g run_tests -t halt test/test_compose.pl

## Reading refusals by recurrence: the same refusal across many scopes is a
## policy gap, one alone is worth a look. FILE holds Scope-Verdict terms.
test-triage:
	$(SWIPL) -q -g run_tests -t halt test/test_triage.pl

triage:
	@test -n "$(FILE)" || { echo "usage: make triage FILE=refusals.pl"; exit 2; }
	$(SWIPL) -q -g "triage_file('$(FILE)')" -t halt tools/triage.pl

## The judge worker: reader fixtures in-process, protocol tests against a spawned worker.
test-worker:
	$(SWIPL) -q -g run_tests -t halt test/test_worker.pl

## Seeded random goals and clauses; properties every generated term must satisfy.
test-generated:
	$(SWIPL) -q -g run_tests -t halt test/test_generated.pl

test-fixtures:
	$(SWIPL) -q -g run_tests -t halt test/test_hornguard.pl

test-policy:
	$(SWIPL) -q -g run_tests -t halt test/test_policy.pl

## Enumerate every engine predicate against library(sandbox); fails on any
## admit that sandbox refuses or any refusal nobody has explained.
test-differential:
	$(SWIPL) -q -g run_tests -t halt test/test_differential.pl

## Disable one walker rule at a time; every mutant must fail the suite.
mutation:
	python3 tools/mutate.py

## The Rust client: fmt, clippy, and integration tests against a real worker.
test-crate:
	cd crates/hornguard && $(CARGO) fmt --check
	cd crates/hornguard && $(CARGO) clippy --all-targets -- -D warnings
	cd crates/hornguard && $(CARGO) test

## Print the full differential report.
differential:
	$(SWIPL) -q -g "all_profiles(P), differential(P)" -t halt tools/differential.pl

## Regenerate the engine manifests by running a probe inside each engine.
## Needs scryer-prolog and tpl on PATH; skips an engine that is not there.
manifests:
	@for b in scryer trealla; do \
	  exe=$$( [ $$b = scryer ] && echo scryer-prolog || echo tpl ); \
	  if command -v $$exe >/dev/null 2>&1; then \
	    $(SWIPL) -q -g "gen_probe($$b, '/tmp/hg_$$b.pl', '/tmp/hg_probe_$$b.pl')" -t halt tools/gen_engine_manifest.pl && \
	    $$exe /tmp/hg_probe_$$b.pl && \
	    $(SWIPL) -q -g "assemble($$b, '/tmp/hg_$$b.pl', 'profiles/engine_$$b.pl')" -t halt tools/gen_engine_manifest.pl; \
	  else echo "skipping $$b: $$exe not on PATH"; fi; \
	done

## Regenerate profiles/swi.pl from the engine. Review the diff before committing.
gen-profiles:
	$(SWIPL) -q -g gen_swi_profiles -t halt tools/gen_swi_profiles.pl

## Judge Prolog source files as a host would judge a library before installing
## it: every clause, then the file as a program. FILES is a space-separated list.
##   make judge FILES="path/a.pl path/b.pl" [JUDGE_OPTS="[dynamic_dispatch(judged)]"]
JUDGE_OPTS ?= []
judge:
	@test -n "$(FILES)" || { echo "usage: make judge FILES=\"a.pl b.pl\""; exit 2; }
	$(SWIPL) -q -g "judge_files([$(shell echo $(FILES) | sed "s/[^ ]*/'&'/g; s/ /,/g")], $(JUDGE_OPTS))" -t halt tools/judge_files.pl

## Run the judge worker on stdin/stdout.
worker:
	$(SWIPL) -q prolog/hornguard_worker_main.pl

## Load every Prolog file once so syntax errors surface without the suite.
check:
	$(SWIPL) -q -g "load_files(['profiles/iso.pl','profiles/prologue.pl','profiles/pinned.pl'],[silent(true)])" -t halt
	$(SWIPL) -q -g "use_module('prolog/hornguard')" -t halt
