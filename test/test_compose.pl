:- module(test_compose, []).

%% Composition and integration: the pieces together, end to end.
%%
%% Fixtures say what the judge decides; attestation says what a predicate
%% does; these say what happens when a term goes the whole way — through the
%% reader and judge, out as canonical text, back in as a term, and run in the
%% tripwired sandbox — and when the runtime half takes over at a sink.

:- use_module(library(plunit)).
:- use_module(library(lists)).
:- use_module('../prolog/hornguard').
:- use_module('../prolog/hornguard_worker').
:- use_module('../tools/attest').

:- dynamic fixture_admit/4.        % Id, Backend, Profiles, Term

load_admit_fixtures :-
    retractall(fixture_admit(_, _, _, _)),
    module_property(test_compose, file(File)),
    file_directory_name(File, Here),
    atomic_list_concat([Here, '/../fixtures/verdicts'], Dir0),
    absolute_file_name(Dir0, Dir),
    directory_files(Dir, Fs),
    forall(( member(F, Fs), file_name_extension(_, pl, F) ),
           ( directory_file_path(Dir, F, P),
             setup_call_cleanup(open(P, read, In), read_admits(In), close(In)) )).

read_admits(In) :-
    read_term(In, T, []),
    (   T == end_of_file -> true
    ;   ( T = verdict(Id, B, Ps, Term, admit), memberchk(B, [iso, swi]) -> assertz(fixture_admit(Id, B, Ps, Term)) ; true ),
        read_admits(In)
    ).

:- initialization(load_admit_fixtures).

%   A term through the whole path: judged, emitted, re-read, run.
round_trip_and_run(Text, Profiles, Options, Verdict, Wires) :-
    hornguard_worker:hornguard_judge_text(judge_goal, Text,
                                          [backend(swi), profiles(Profiles)|Options], Resp),
    get_dict(verdict, Resp, Verdict),
    (   memberchk(Verdict, [admit, admit_with])
    ->  get_dict(canonical, Resp, C),
        term_string(Term, C),
        in_scratch(( calibrate(Noise), run_goal(Term, Noise, Wires) ))
    ;   Wires = not_run
    ).

:- begin_tests(compose).

% Every fixture the judge admits on an engine we have runs inert. This is
% the fixtures and the attestation meeting: a hand-written admit that
% tripped a wire would be a wrong fixture or a wrong allow.
test(admitted_fixtures_run_inert, [ forall(fixture_admit(Id, _, _, Term)), true(Ok == yes) ]) :-
    in_scratch(( calibrate(Noise), copy_term(Term, Run), run_goal(Run, Noise, Wires) )),
    (   Wires == [] -> Ok = yes
    ;   format(user_error, "~n  fixture ~w tripped ~q~n", [Id, Wires]), Ok = Wires
    ).

% Nested meta-predicates, closures completed, negation and aggregation:
% admitted as a whole, and inert as a whole.
test(nested_meta_composition_is_admitted_and_inert, [true(( V == admit, W == [] ))]) :-
    round_trip_and_run(
        "forall(member(X, [1, 2, 3]), (findall(Y, between(1, X, Y), L), maplist(succ, L, _), \\+ memberchk(0, L)))",
        [iso, prologue, swi, swi_lists, swi_apply], [], V, W).

% The canonical form is what runs. A term with operators and a quoted atom
% goes out operator-free and comes back the same term.
test(canonical_text_round_trips_to_the_same_term, [true(T2 =@= T1)]) :-
    T1 = (X is 1 + 2 * 3, atom_length('it''s', N), N > X),
    hornguard_worker:hornguard_canonical(T1, C),
    term_string(T2, C).

% Judged dispatch end to end: the rewritten term runs, and a sink that binds
% to a pinned goal refuses at run time with the runtime wrapper, inside the
% sandbox, tripping no wire on the way.
test(judged_sink_refuses_at_runtime_and_trips_nothing,
     [true(( V == admit_with, E = error(permission_error(execute, goal, shell/1), hornguard(_, runtime(_))), W == [] ))]) :-
    hornguard_worker:hornguard_judge_text(judge_goal, "G = shell(x), call(G)",
        [backend(swi), profiles([iso]), dynamic_dispatch(judged)], Resp),
    get_dict(verdict, Resp, V),
    get_dict(canonical, Resp, C),
    term_string(Term, C),
    in_scratch(( calibrate(Noise),
                 run_goal(catch(Term, E0, nb_setval(hg_compose_caught, E0)), [globals-hg_compose_caught|Noise], W) )),
    nb_getval(hg_compose_caught, E),
    nb_delete(hg_compose_caught).

% ...and a sink that binds to a pure goal runs it.
test(judged_sink_runs_a_pure_goal, [true(( V == admit_with, W == [], Ran == yes ))]) :-
    hornguard_worker:hornguard_judge_text(judge_goal, "G = atom_length(abc, 3), call(G), maplist(call, [atom(a), atom(b)])",
        [backend(swi), profiles([iso, prologue]), dynamic_dispatch(judged)], Resp),
    get_dict(verdict, Resp, V),
    get_dict(canonical, Resp, C),
    term_string(Term, C),
    in_scratch(( calibrate(Noise),
                 run_goal(( Term -> nb_setval(hg_compose_ran, yes) ; nb_setval(hg_compose_ran, no) ),
                          [globals-hg_compose_ran|Noise], W) )),
    nb_getval(hg_compose_ran, Ran),
    nb_delete(hg_compose_ran).

% A stored program under judged dispatch: clauses rewritten, loaded into a
% fresh module, called with a goal constructed at run time from data. The
% pure path answers; the pinned path refuses with the runtime wrapper.
test(a_judged_program_runs_and_refuses_at_its_sinks,
     [ cleanup(catch(hornguard_compose_prog:abolish_all_tables, _, true)),
       true(( Answer == yes, E = error(_, hornguard(_, runtime(_))) )) ]) :-
    Clauses = [ (apply_all([], _) :- true),
                (apply_all([G|Gs], X) :- call(G, X), apply_all(Gs, X)) ],
    hornguard_admit_program(swi, [iso, prologue], Clauses, [dynamic_dispatch(judged)], admit_with(Guarded)),
    add_import_module(hornguard_compose_prog, hornguard, end),
    forall(member(Cl, Guarded), assertz(hornguard_compose_prog:Cl)),
    (   hornguard_compose_prog:apply_all([integer, atom_length(a)], 1) -> Answer = yes ; Answer = no ),
    catch(hornguard_compose_prog:apply_all([atom, shell], x), E, true),
    forall(member(Cl, Guarded), ( ( Cl = (H :- _) -> true ; H = Cl ), retractall(hornguard_compose_prog:H) )).

% Refused terms never reach an engine: the worker returns no canonical form
% for them, so there is nothing a host could run by mistake.
test(refused_terms_carry_nothing_to_run, [true(( V == refused, \+ get_dict(canonical, Resp, _) ))]) :-
    hornguard_worker:hornguard_judge_text(judge_goal, "findall(X, current_prolog_flag(home, X), L)",
        [backend(swi), profiles([iso])], Resp),
    get_dict(verdict, Resp, V).

% A host-declared operator all the way: read with the operator, judged,
% emitted operator-free, re-read by an engine that never heard of it.
test(host_operator_survives_the_round_trip,
     [cleanup(( op(0, xfx, hornguard_worker:'::'), hornguard:hg_default_dir(D0), hornguard_load_profiles(D0) )),
      true(( V == admit, T =@= ('::'(a, b) = '::'(a, b)) ))]) :-
    tmp_file(hg_ops2, Dir), make_directory(Dir),
    directory_file_path(Dir, 'ops.pl', F),
    setup_call_cleanup(open(F, write, S), format(S, "op(600, xfx, ::).~n", []), close(S)),
    hornguard:hg_default_dir(D),
    hornguard_load_profiles([D, Dir]),
    hornguard_worker:apply_ops,
    hornguard_worker:hornguard_judge_text(judge_goal, "a :: b = a :: b", [backend(iso), profiles([iso])], Resp),
    get_dict(verdict, Resp, V),
    get_dict(canonical, Resp, C),
    term_string(T0, C),
    T = T0.

:- end_tests(compose).
