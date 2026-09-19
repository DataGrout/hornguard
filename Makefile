SWIPL ?= swipl

.PHONY: test test-fixtures test-policy test-generated test-worker test-differential check differential gen-profiles mutation worker

test: test-fixtures test-policy test-generated test-worker test-differential

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

## Print the full differential report.
differential:
	$(SWIPL) -q -g "all_profiles(P), differential(P)" -t halt tools/differential.pl

## Regenerate profiles/swi.pl from the engine. Review the diff before committing.
gen-profiles:
	$(SWIPL) -q -g gen_swi_profiles -t halt tools/gen_swi_profiles.pl

## Run the judge worker on stdin/stdout.
worker:
	$(SWIPL) -q prolog/hornguard_worker_main.pl

## Load every Prolog file once so syntax errors surface without the suite.
check:
	$(SWIPL) -q -g "load_files(['profiles/iso.pl','profiles/prologue.pl','profiles/pinned.pl'],[silent(true)])" -t halt
	$(SWIPL) -q -g "use_module('prolog/hornguard')" -t halt
