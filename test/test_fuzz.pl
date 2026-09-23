:- module(test_fuzz, []).

%% Admit-then-run. Terms an author might write, built from allowed and pinned
%% vocabulary; every one the judge admits is executed in the tripwired
%% sandbox. A wire on an admitted term is a composition failure. The seed is
%% fixed so a failure reproduces; a bigger N or another seed is `make fuzz`.

:- use_module(library(plunit)).
:- use_module(library(lists)).
:- use_module(library(aggregate)).
:- use_module('../tools/fuzz').

:- begin_tests(fuzz).

test(admitted_terms_run_clean, [true(Failures == [])]) :-
    fuzz_report(400, 20260922, Report),
    findall(T-W, member(composition_failure(T, W), Report), Failures),
    (   Failures == [] -> true
    ;   forall(member(T-W, Failures), format(user_error, "~ncomposition failure: ~q~n  ~q~n", [T, W]))
    ).

test(the_generator_exercises_both_verdicts, [true(( NA > 50, NR > 50 ))]) :-
    fuzz_report(400, 20260922, Report),
    aggregate_all(count, member(admitted(_), Report), NA),
    aggregate_all(count, member(refused(_, _, _), Report), NR).

test(every_pinned_term_generated_was_refused_not_run, [true(Leaked == [])]) :-
    % A term with a pinned predicate in call position must never reach the
    % sandbox: if it did, it would be in admitted/1. Check the admitted terms
    % carry no pinned functor in a call position by re-judging each.
    fuzz_report(400, 20260922, Report),
    findall(T, ( member(admitted(T), Report),
                 hornguard:hornguard_admit(swi, [iso, prologue, swi, swi_lists, swi_apply, swi_aggregate, swi_strings, swi_pairs, swi_ordsets, swi_terms], T, [strict_negation(false)], V),
                 V \== admit ),
            Leaked).

test(a_different_seed_is_also_clean, [true(Failures == [])]) :-
    fuzz_report(200, 7, Report),
    findall(T, member(composition_failure(T, _), Report), Failures).

:- end_tests(fuzz).
