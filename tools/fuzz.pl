:- module(hornguard_fuzz,
          [ fuzz/0,                   % 400 terms, seed 20260922; fails on any finding
            fuzz/2,                   % +N, +Seed
            fuzz_report/3,            % +N, +Seed, -Report
            fuzz_terms/3              % +N, +Seed, -[Term-Expect]
          ]).

%% Admit-then-run: fuzzing and attestation in one loop.
%%
%% The attestation harness calls allowed predicates one at a time. This
%% builds terms the way an author would, and the way an adversary would:
%% allowed predicates nested in allowed meta-predicates under control
%% constructs, and pinned goals placed where a judge can lose sight of
%% them: in a list handed to call/1, behind a unification or =../2 or
%% functor/3, under negation, inside catch/3, in the untaken branch of an
%% if-then-else, module-qualified, as a closure completed at the call.
%%
%% Every term is judged. Every term the judge ADMITS is executed in the
%% tripwired sandbox, and a wire that trips is a composition failure. Every
%% term built with a pinned goal in a position that runs is tagged `refuse`,
%% and an admitted one is an unexpected admit whether or not it tripped.
%%
%% The pinned goals used are canaries: harmless, and visible to a tripwire
%% (a written atom, a global, an operator, a fact, a scratch file, a record,
%% a read flag). A judge that misses one shows up as a wire, never as a real
%% effect. Refused terms are never run.
%%
%% Seeded, so a failure reproduces. fuzz/0 uses the seed the test uses.
%%
%%   swipl -q -g fuzz -t halt tools/fuzz.pl              (or: make fuzz)
%%   swipl -q -g "fuzz(2000, 7)" -t halt tools/fuzz.pl

:- use_module(library(lists)).
:- use_module(library(apply)).
:- use_module(library(random)).
:- use_module('../prolog/hornguard').
:- use_module(attest).

default_n(400).
default_seed(20260922).
profiles([iso, prologue, swi, swi_lists, swi_apply, swi_aggregate, swi_strings, swi_pairs, swi_ordsets, swi_terms]).

fuzz :-
    default_n(N), default_seed(Seed),
    fuzz(N, Seed).

fuzz(N, Seed) :-
    fuzz_report(N, Seed, Report),
    print_report(N, Seed, Report),
    \+ memberchk(composition_failure(_, _), Report),
    \+ memberchk(unexpected_admit(_, _), Report).

%!  fuzz_terms(+N, +Seed, -Tagged) is det.
%
%   The generated terms with what the generator knows about each: `refuse`
%   when a pinned goal or an unbound goal stands where it would run, `any`
%   otherwise.

fuzz_terms(N, Seed, Tagged) :-
    hornguard_profiles(_),
    set_random(seed(Seed)),
    vocabulary(Pure, Meta, Canaries),
    findall(T-E, ( between(1, N, _), gen_goal(0, Pure, Meta, Canaries, T-E) ), Tagged).

%!  fuzz_report(+N, +Seed, -Report) is det.
%
%   Report entries: admitted(Term) | refused(Term, Class, Rule) |
%   needs(Term, Needs) | composition_failure(Term, Wires) |
%   unexpected_admit(Term, Wires).

fuzz_report(N, Seed, Report) :-
    fuzz_terms(N, Seed, Tagged),
    profiles(Ps),
    hornguard_attest:prime,
    in_scratch(( calibrate(Noise),
                 maplist(judge_and_run(Ps, Noise), Tagged, Report) )).

judge_and_run(Ps, Noise, Term-Expect, Entry) :-
    hornguard_admit(swi, Ps, Term, [strict_negation(false)], V),
    (   V == admit
    ->  copy_term(Term, Run),
        run_goal(Run, Noise, Wires),
        (   Expect == refuse -> Entry = unexpected_admit(Term, Wires)
        ;   Wires == [] -> Entry = admitted(Term)
        ;   spec_ok(Wires, Term) -> Entry = admitted(Term)
        ;   Entry = composition_failure(Term, Wires)
        )
    ;   V = admit_needs(Needs) -> Entry = needs(Term, Needs)
    ;   V = refused(_, Class, Rule) -> Entry = refused(Term, Class, Rule)
    ).

%   A wire the profiles declare (randomness) is not a failure.
spec_ok(Wires, Term) :-
    forall(member(wire(Name, _), Wires),
           ( Name == random,
             term_functors(Term, Fs),
             member(F, Fs), expected(_, F, random_state) )).

term_functors(T, []) :- var(T), !.
term_functors(T, [N/A|Fs]) :-
    compound(T), !,
    functor(T, N, A), T =.. [_|Args],
    foldl(functors_acc, Args, [], Fs).
term_functors(T, [T/0]) :- atom(T), !.
term_functors(_, []).

functors_acc(X, Acc0, Acc) :- term_functors(X, FX), append(FX, Acc0, Acc).

		 /*******************************
		 *          VOCABULARY          *
		 *******************************/

%   Pure: allowed predicates that take no goal argument. Meta: allowed
%   predicates with a spec. Canaries: pinned goals that are harmless and
%   that a tripwire sees, so a judge miss is observable and safe.
vocabulary(Pure, Meta, Canaries) :-
    profiles(Ps),
    findall(N/A, ( member(P, Ps), hornguard:hg_allow(P, N/A),
                   \+ hornguard:hg_any_meta_spec(N/A, _),
                   \+ hornguard:hg_control_indicator(N/A),
                   N \== halt, N \== (!) ), Pure0),
    sort(Pure0, Pure),
    findall(N/A-Spec, ( member(P, Ps), hornguard:hg_allow(P, N/A),
                        hornguard:hg_any_meta_spec(N/A, Spec) ), Meta0),
    sort(Meta0, Meta),
    findall(C, ( canary(C), functor(C, N, A), pinned_here(N/A) ), Canaries),
    Canaries \== [].

pinned_here(N/A) :- hornguard:hg_pinned(_, N/A), !.
pinned_here(N/_) :- hornguard:hg_pinned(_, N), !.

canary(write(hg_canary)).                          % output
canary(nb_setval(hg_fuzz_canary, 1)).              % globals
canary(op(700, xfx, hg_fuzz_canary_op)).           % ops
canary(assertz(hg_fuzz_canary_fact)).              % dynpreds
canary(open('hg_fuzz_canary.txt', write, _)).      % streams, files
canary(recordz(hg_fuzz_canary, x)).                % records
canary(current_prolog_flag(home, _)).              % reconnaissance; no wire, the tag catches it
canary(set_random(seed(1))).                       % random

data_value(a).
data_value(1).
data_value(2.5).
data_value("s").
data_value([a, b]).
data_value([]).
data_value(f(x)).
data_value(_).

		 /*******************************
		 *          GENERATOR           *
		 *******************************/

%   Every generated term carries what the generator knows: `refuse` when a
%   canary or an unbound goal stands where it runs, `any` otherwise. A
%   canary as data (an argument of a pure predicate) is `any`: the judge is
%   right to admit it, and the run shows it stayed data.
gen_goal(D, Pure, Meta, Cs, T-E) :-
    random_between(1, 100, R),
    (   D >= 4 -> gen_leaf(Pure, Cs, T-E)
    ;   R =< 30 -> gen_leaf(Pure, Cs, T-E)
    ;   R =< 50 -> gen_control(D, Pure, Meta, Cs, T-E)
    ;   R =< 75 -> gen_meta(D, Pure, Meta, Cs, T-E)
    ;   gen_evasion(D, Pure, Meta, Cs, T-E)
    ).

gen_leaf(Pure, Cs, T-E) :-
    random_between(1, 100, R),
    (   R =< 85
    ->  random_member(N/A, Pure), gen_args(A, Cs, Args), T =.. [N|Args], E = any
    ;   R =< 96
    ->  random_member(T, Cs), E = refuse
    ;   T = _, E = refuse
    ).

%   Data arguments: plain values, and now and then a canary as a term, so
%   pinned functors appear in data position where they are admissible.
gen_args(A, Cs, Args) :-
    length(Args, A),
    maplist(gen_arg(Cs), Args).

gen_arg(Cs, X) :-
    random_between(1, 100, R),
    (   R =< 90 -> findall(V, data_value(V), Vs), random_member(X, Vs)
    ;   random_member(C, Cs), copy_term(C, X)
    ).

gen_control(D, Pure, Meta, Cs, T-E) :-
    D1 is D + 1,
    gen_goal(D1, Pure, Meta, Cs, A-EA),
    gen_goal(D1, Pure, Meta, Cs, B-EB),
    join(EA, EB, EAB),
    random_member(T-E, [ (A, B)-EAB, (A ; B)-EAB, (A -> B)-EAB, (A *-> B)-EAB,
                         (A -> B ; true)-EAB, (\+ A)-EA, (A, \+ B)-EAB ]).

gen_meta(D, Pure, Meta, Cs, T-E) :-
    D1 is D + 1,
    random_member(N/_-Spec, Meta),
    Spec =.. [_|Modes],
    maplist(gen_mode_arg(D1, Pure, Meta, Cs), Modes, Args, Es),
    T =.. [N|Args],
    foldl(join, Es, any, E).

gen_mode_arg(D, Pure, Meta, Cs, 0, G, E) :- !, gen_goal(D, Pure, Meta, Cs, G-E).
gen_mode_arg(D, Pure, Meta, Cs, ^, G, E) :- !, gen_goal(D, Pure, Meta, Cs, G-E).
gen_mode_arg(_, Pure, _, Cs, K, C, E) :-
    integer(K), K > 0, !,
    % a closure: an allowed predicate or a canary missing its last K arguments
    random_between(1, 100, R),
    (   R =< 80
    ->  random_member(N/A, Pure), Keep is max(0, A - K), gen_args(Keep, Cs, Args), C =.. [N|Args], E = any
    ;   random_member(Canary, Cs), closure_of(Canary, K, C), E = refuse
    ).
gen_mode_arg(_, _, _, Cs, _, V, any) :-
    gen_arg(Cs, V).

closure_of(Canary, K, C) :-
    Canary =.. [N|Args],
    length(Args, A),
    Keep is max(0, A - K),
    length(Front, Keep),
    append(Front, _, Args),
    C =.. [N|Front].

join(refuse, _, refuse) :- !.
join(_, refuse, refuse) :- !.
join(_, _, any).

%   The shapes a judge can lose a goal in. Each puts a canary where it
%   would run, so each is `refuse`; some are wrapped in pure context so the
%   canary is not the first thing the walk sees.
gen_evasion(D, Pure, Meta, Cs, T-refuse) :-
    random_member(C, Cs),
    evasion_shapes(C, Shapes),
    random_member(Ev, Shapes),
    random_between(1, 100, R),
    (   R =< 60 -> T = Ev
    ;   D1 is D + 1,
        gen_goal(D1, Pure, Meta, Cs, P-_),
        random_member(T, [ (P, Ev), (Ev, P), (P -> Ev ; true), findall(x, (P, Ev), _), forall(P, Ev) ])
    ).

evasion_shapes(C, Shapes) :-
    C =.. [N|Args],
    (   Args = [] -> ClosureShapes = []
    ;   append(Front, [Last], Args), Cl =.. [N|Front],
        ClosureShapes = [ call(Cl, Last), maplist(Cl, [Last]), (G4 = Cl, call(G4, Last)),
                          foldl([_, _, _]>>call(Cl, Last), [a], 0, _) ]
    ),
    term_to_atom(C, Text),
    Shapes0 = [ maplist(call, [C]),
                forall(member(G1, [C]), call(G1)),
                (member(G2, [true, C]), call(G2)),
                (G3 = C, call(G3)),
                (G5 = C, G5),
                (C =.. L1, G6 =.. L1, call(G6)),
                (functor(C, N7, A7), functor(G7, N7, A7), call(G7)),
                (term_to_atom(G8, Text), call(G8)),
                \+ \+ C,
                \+ C,
                catch(C, _, true),
                findall(x, C, _),
                bagof(x, C, _),
                setof(x, C, _),
                aggregate_all(count, C, _),
                user:C,
                system:C,
                (fail -> true ; C),
                (true ; C),
                (C *-> true ; true),
                once(C),
                ignore(C),
                call(C),
                call((true, C)),
                forall(true, C),
                (C, true),
                (true, C) ],
    append(Shapes0, ClosureShapes, Shapes).

		 /*******************************
		 *            REPORT            *
		 *******************************/

print_report(N, Seed, Report) :-
    aggregate_all(count, member(admitted(_), Report), NA),
    aggregate_all(count, member(refused(_, _, _), Report), NR),
    aggregate_all(count, member(needs(_, _), Report), NN),
    aggregate_all(count, member(composition_failure(_, _), Report), NF),
    aggregate_all(count, member(unexpected_admit(_, _), Report), NU),
    forall(member(composition_failure(T, Ws), Report),
           ( format("COMPOSITION FAILURE~n  ~q~n", [T]), print_wires(Ws) )),
    forall(member(unexpected_admit(T, Ws), Report),
           ( format("UNEXPECTED ADMIT (a pinned goal stood where it runs)~n  ~q~n", [T]), print_wires(Ws) )),
    findall(Class, member(refused(_, Class, _), Report), Classes),
    msort(Classes, Sorted), clumped(Sorted, Counts),
    format("~d terms, seed ~w: ~d admitted and run clean, ~d refused ~q, ~d with needs, ~d composition failures, ~d unexpected admits~n",
           [N, Seed, NA, NR, Counts, NN, NF, NU]).

print_wires(Ws) :-
    forall(member(wire(W, Dt), Ws),
           ( term_to_atom(Dt, DA),
             (   atom_length(DA, Len), Len > 160 -> sub_atom(DA, 0, 160, _, S) ; S = DA ),
             format("    ~w: ~w~n", [W, S]) )).
