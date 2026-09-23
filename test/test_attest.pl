:- module(test_attest, []).

%% Attestation by experiment: the harness must catch each kind of impurity a
%% profile line could hide, leave a pure predicate alone, and find nothing
%% undeclared in the shipped profiles on this engine.

:- use_module(library(plunit)).
:- use_module(library(lists)).
:- use_module('../tools/attest').

% Probes. Each does one thing a pure predicate must not.
:- dynamic probe_fact/1.

probe_pure(X) :- X = 1.
probe_output(_) :- write(hello).
probe_message(_) :- print_message(warning, format("probe", [])).
probe_global(_) :- nb_setval(hg_attest_probe_key, 1).
probe_assert(_) :- assertz(probe_fact(1)).
probe_new_module(_) :- assertz(hg_attest_probe_module:fact(1)).
probe_file(_) :- open('hg_attest_probe.txt', write, S), close(S).
probe_stream(_) :- open('hg_attest_probe_open.txt', write, _).
% A global flag: double_quotes would be module-local and, correctly, unseen.
probe_flag(_) :- set_prolog_flag(gc, false).
probe_op(_) :- op(700, xfx, hg_probe_op).
probe_record(_) :- recordz(hg_attest_probe, x).
probe_cwd(_) :- working_directory(_, '..').
probe_random(_) :- random_between(1, 10, _).
% Writes past current output, to the alias by name.
probe_alias(_) :- format(user_error, "probe", []).
% Impure only for one argument value: quiet under generic shapes, caught
% by the positional sweep.
probe_positional(S) :- ( S == user_error -> format(user_error, "probe", []) ; true ).
probe_positional_file(F) :- ( F == 'hg_attest_probe.txt' -> open(F, write, St), close(St) ; true ).

:- begin_tests(attest).

test(pure_is_pure, [true(V == pure)]) :-
    attest_predicate(test_attest:probe_pure/1, V).

test(output_trips, [true(W == output)]) :-
    attest_predicate(test_attest:probe_output/1, impure([_-[wire(W, _)|_]|_])).

test(message_trips, [true(W == messages)]) :-
    attest_predicate(test_attest:probe_message/1, impure([_-[wire(W, _)|_]|_])).

test(global_trips, [true(Ws = [wire(globals, keys([hg_attest_probe_key]))|_])]) :-
    attest_predicate(test_attest:probe_global/1, impure([_-Ws|_])),
    nb_delete(hg_attest_probe_key).

test(assert_trips, [true(memberchk(wire(dynpreds, _), Ws))]) :-
    attest_predicate(test_attest:probe_assert/1, impure([_-Ws|_])),
    retractall(probe_fact(_)).

test(new_module_trips, [true(memberchk(wire(modules, _), Ws))]) :-
    attest_predicate(test_attest:probe_new_module/1, impure([_-Ws|_])).

test(file_trips, [true(memberchk(wire(files, _), Ws))]) :-
    attest_predicate(test_attest:probe_file/1, impure([_-Ws|_])).

test(open_stream_trips, [true(memberchk(wire(streams, _), Ws))]) :-
    attest_predicate(test_attest:probe_stream/1, impure([_-Ws|_])),
    forall(( stream_property(S, file_name(F)), sub_atom(F, _, _, _, hg_attest_probe_open) ),
           close(S)).

test(flag_trips, [true(memberchk(wire(flags, keys([gc])), Ws))]) :-
    current_prolog_flag(gc, GC),
    attest_predicate(test_attest:probe_flag/1, impure([_-Ws|_])),
    set_prolog_flag(gc, GC).

test(op_trips, [true(memberchk(wire(ops, _), Ws))]) :-
    attest_predicate(test_attest:probe_op/1, impure([_-Ws|_])),
    op(0, xfx, hg_probe_op).

test(record_trips, [true(memberchk(wire(records, _), Ws))]) :-
    attest_predicate(test_attest:probe_record/1, impure([_-Ws|_])),
    forall(recorded(hg_attest_probe, _, R), erase(R)).

test(cwd_trips, [true(memberchk(wire(cwd, _), Ws))]) :-
    attest_predicate(test_attest:probe_cwd/1, impure([_-Ws|_])).

test(random_trips, [true(memberchk(wire(random, _), Ws))]) :-
    attest_predicate(test_attest:probe_random/1, impure([_-Ws|_])).

test(alias_output_trips, [true(memberchk(wire(alias_output, [user_error-"probe"]), Ws))]) :-
    attest_predicate(test_attest:probe_alias/1, impure([_-Ws|_])).

test(positional_sweep_finds_a_value_dependent_write, [true(memberchk(wire(alias_output, _), Ws))]) :-
    attest_predicate(test_attest:probe_positional/1, impure(Fired)),
    member(_-Ws, Fired), memberchk(wire(alias_output, _), Ws), !.

test(positional_sweep_finds_a_value_dependent_file, [true(memberchk(wire(files, _), Ws))]) :-
    attest_predicate(test_attest:probe_positional_file/1, impure(Fired)),
    member(_-Ws, Fired), memberchk(wire(files, _), Ws), !.

test(undefined_is_skipped, [true(V == skipped(undefined))]) :-
    attest_predicate(no_such_predicate_hg/3, V).

% The claim the profiles make, checked against this engine. Randomness is
% declared; anything else that moves is a line to pin or drop.
test(shipped_profiles_hide_no_undeclared_impurity, [true(Impure == [])]) :-
    attest_report(all, Report),
    findall(P-I, member(P-I-impure(_), Report), Impure),
    (   Impure == [] -> true
    ;   format(user_error, "~nundeclared impurities: ~q~n", [Impure])
    ).

test(randomness_is_declared_not_hidden, [true(Undeclared == [])]) :-
    attest_report([swi_random], Report),
    findall(I, member(_-I-impure(_), Report), Undeclared).

:- end_tests(attest).
