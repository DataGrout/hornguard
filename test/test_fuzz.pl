:- module(test_fuzz, []).

%% Admit-then-run. Terms an author or an adversary might write, built from
%% allowed vocabulary with harmless pinned canaries placed where a judge can
%% lose sight of them. Every admitted term runs in the tripwired sandbox; a
%% wire is a composition failure, and an admitted term built with a canary
%% where it runs is an unexpected admit whether or not it tripped. The seed
%% is fixed so a failure reproduces; `make fuzz` takes another count or seed.

:- use_module(library(plunit)).
:- use_module(library(lists)).
:- use_module(library(aggregate)).
:- use_module(library(occurs)).
:- use_module('../tools/fuzz').

:- begin_tests(fuzz).

test(admitted_terms_run_clean, [true(Failures == [])]) :-
    fuzz_report(400, 20260922, Report),
    findall(T-W, member(composition_failure(T, W), Report), Failures),
    forall(member(T-W, Failures), format(user_error, "~ncomposition failure: ~q~n  ~q~n", [T, W])).

% The property the generator can state: a canary standing where it would
% run, however it got there, is refused. An admit here is a judge miss.
test(a_pinned_goal_where_it_runs_is_refused, [true(Misses == [])]) :-
    fuzz_report(400, 20260922, Report),
    findall(T-W, member(unexpected_admit(T, W), Report), Misses),
    forall(member(T-W, Misses), format(user_error, "~nunexpected admit: ~q~n  ~q~n", [T, W])).

% A canary in data position is admissible and, run, stays data.
test(a_pinned_functor_as_data_is_admitted_and_inert, [true(( NData > 20, Bad == [] ))]) :-
    fuzz_terms(400, 20260922, Tagged),
    fuzz_report(400, 20260922, Report),
    aggregate_all(count, ( member(T-any, Tagged), carries_canary(T) ), NData),
    findall(T, ( member(T-any, Tagged), carries_canary(T),
                 \+ memberchk(admitted(T), Report), \+ memberchk(refused(T, _, _), Report),
                 \+ memberchk(needs(T, _), Report) ), Bad).

carries_canary(T) :-
    sub_term(S, T), compound(S), functor(S, N, _),
    memberchk(N, [write, nb_setval, op, assertz, open, recordz, current_prolog_flag, set_random]), !.

% The generator reaches both verdicts and the evasion shapes.
test(the_generator_covers_the_ground, [true(( NA > 50, NR > 100, NE > 40 ))]) :-
    fuzz_terms(400, 20260922, Tagged),
    fuzz_report(400, 20260922, Report),
    aggregate_all(count, member(admitted(_), Report), NA),
    aggregate_all(count, member(_-refuse, Tagged), NR),
    aggregate_all(count, ( member(T-refuse, Tagged), evasion_marker(T) ), NE).

evasion_marker(T) :-
    sub_term(S, T), compound(S),
    ( S = maplist(call, _) ; S = call(_, _) ; S = (_ =.. _) ; S = functor(_, _, _) ; S = catch(_, _, _)
    ; S = term_to_atom(_, _) ; S = (_:_) ; S = bagof(_, _, _) ; S = setof(_, _, _) ; S = aggregate_all(_, _, _) ), !.

test(a_different_seed_is_also_clean, [true(( Failures == [], Misses == [] ))]) :-
    fuzz_report(200, 7, Report),
    findall(T, member(composition_failure(T, _), Report), Failures),
    findall(T, member(unexpected_admit(T, _), Report), Misses).

:- end_tests(fuzz).
