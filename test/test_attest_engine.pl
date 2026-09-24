:- module(test_attest_engine, []).

%% The engine attestation harness, checked against goals whose effects are
%% known: the wires must fire on the impure ones and stay quiet on the pure
%% ones, inside each engine that is on PATH. Without an engine the unit is
%% skipped, not failed; CI installs both.

:- use_module(library(plunit)).
:- use_module(library(lists)).
:- use_module(library(pairs)).
:- use_module('../tools/attest_engine').

%   The engines to test are the ones on PATH. This is the forall/1
%   generator, not a condition/1: plunit evaluates a condition before the
%   generator binds its variable, so a condition on B would run once with B
%   unbound and skip nothing.
:- dynamic noted_absent/1.

engine(B) :-
    member(B, [scryer, trealla]),
    (   engine_available(B)
    ->  true
    ;   (   noted_absent(B) -> true
        ;   assertz(noted_absent(B)),
            format(user_error, "~n  ~w not on PATH; its engine attestation is skipped~n", [B])
        ),
        fail
    ).

%   The verdict of one goal, run by itself.
verdict_of(B, Goal, V) :-
    attest_engine_goals(B, [probe-Goal], [probe-V]).

fires(impure(Fired), Wire) :-
    once(( member(_-Ws, Fired), memberchk(Wire, Ws) )).

fires_any(V, Wires) :-
    once(( member(W, Wires), fires(V, W) )).

:- begin_tests(attest_engine).

test(pure_goals_are_pure, [ forall(engine(B)),
                            true(Vs == [pure, pure, pure, pure, pure]) ]) :-
    attest_engine_goals(B, [ a-atom_length(abc, _), b-(f(X) = f(1)), c-functor(_, g, 2),
                             d-atom_codes(_, "xyz"), e-(X is 1 + 2) ], R),
    pairs_values(R, Vs).

test(output_is_a_wire, [ forall(engine(B)), true(fires(V, output)) ]) :-
    verdict_of(B, write(hello), V).

test(a_new_operator_is_a_wire, [ forall(engine(B)), true(fires(V, ops)) ]) :-
    verdict_of(B, op(700, xfx, hg_probe_op), V).

test(a_changed_flag_is_a_wire, [ forall(engine(B)), true(fires(V, flags)) ]) :-
    verdict_of(B, set_prolog_flag(double_quotes, atom), V).

test(an_asserted_clause_is_a_wire, [ forall(engine(B)),
                                     true(fires_any(V, [dynclauses, preds])) ]) :-
    verdict_of(B, assertz(hg_probe_fact(1)), V).

test(an_opened_stream_is_a_wire, [ forall(engine(B)),
                                   true(fires_any(V, [streams, files])) ]) :-
    verdict_of(B, open('hg_probe_left_open.txt', write, _), V).

test(a_written_file_is_a_wire, [ forall(engine(B)),
                                 true(fires(V, files)) ]) :-
    verdict_of(B, ( open('hg_probe_written.txt', write, S), close(S) ), V).

test(an_undefined_predicate_is_reported_not_passed, [ forall(engine(B)),
                                                       true(V == not_defined) ]) :-
    attest_engine_report(B, [hg_no_such_predicate_xyz/2], [_-V]).

% An engine with call_with_inference_limit/3 stops the loop itself and the
% goal is simply pure; one without is killed from this side. Either way
% the harness comes back.
test(a_runaway_goal_is_bounded_not_a_hang, [ forall(engine(B)),
                                             true(memberchk(V, [timeout, pure])) ]) :-
    verdict_of(B, ( repeat, fail ), V).

% The whole allowed vocabulary the manifest names, inside the engine: no
% undeclared impurity, and nothing the manifest claims that the engine, as
% started, does not define.
test(the_full_profile_is_clean, [ forall(engine(B)), true(Bad == []) ]) :-
    attest_engine_report(B, Report),
    findall(I-V, ( member(I-V, Report), ( V = impure(_) ; V == not_defined ; V = error(_) ) ), Bad),
    forall(member(I-V, Bad), format(user_error, "~n  ~w ~w: ~q~n", [B, I, V])).

:- end_tests(attest_engine).
