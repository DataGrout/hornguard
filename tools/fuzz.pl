:- module(hornguard_fuzz,
          [ fuzz/0,                   % 400 terms, seed 20260922; fails on a composition failure
            fuzz/2,                   % +N, +Seed
            fuzz_report/3             % +N, +Seed, -Report
          ]).

%% Admit-then-run: fuzzing and attestation in one loop.
%%
%% The attestation harness calls allowed predicates one at a time. This
%% builds terms the way an author would, from allowed predicates nested in
%% allowed meta-predicates under control constructs, with pinned predicates
%% mixed in; judges each one; and executes every term the judge ADMITS in
%% the tripwired sandbox. A wire that trips on an admitted term is a
%% composition failure: members the harness found inert did something
%% together, or an allowlist entry is wrong in a way one call did not show.
%% Refused terms are never run; that they are refused is the judge's job and
%% the generated-terms suite already checks it.
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
    \+ memberchk(composition_failure(_, _), Report).

%!  fuzz_report(+N, +Seed, -Report) is det.
%
%   Report entries: admitted(Term) | refused(Term, Class, Rule) |
%   composition_failure(Term, Wires) | needs(Term, Needs).

fuzz_report(N, Seed, Report) :-
    hornguard_profiles(_),
    set_random(seed(Seed)),
    vocabulary(Pure, Meta, Pinned),
    findall(T, ( between(1, N, _), gen_goal(0, Pure, Meta, Pinned, T) ), Terms),
    profiles(Ps),
    hornguard_attest:prime,
    in_scratch(( calibrate(Noise),
                 maplist(judge_and_run(Ps, Noise), Terms, Report) )).

judge_and_run(Ps, Noise, Term, Entry) :-
    hornguard_admit(swi, Ps, Term, [strict_negation(false)], V),
    (   V == admit
    ->  copy_term(Term, Run),
        run_goal(Run, Noise, Wires),
        (   Wires == [] -> Entry = admitted(Term)
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
term_functors(T, [N/A|Fs]) :- compound(T), !, functor(T, N, A), T =.. [_|Args], foldl([X, Acc0, Acc]>>(term_functors(X, FX), append(FX, Acc0, Acc)), Args, [], Fs).
term_functors(T, [T/0]) :- atom(T), !.
term_functors(_, []).

		 /*******************************
		 *          VOCABULARY          *
		 *******************************/

%   Pure: allowed predicates that take no goal argument. Meta: allowed
%   predicates with a spec. Pinned: a pinned indicator with a concrete arity,
%   so the generator produces terms the judge must refuse, at every depth.
vocabulary(Pure, Meta, Pinned) :-
    profiles(Ps),
    findall(N/A, ( member(P, Ps), hornguard:hg_allow(P, N/A),
                   \+ hornguard:hg_any_meta_spec(N/A, _),
                   \+ hornguard:hg_control_indicator(N/A),
                   N \== halt, N \== (!) ), Pure0),
    sort(Pure0, Pure),
    findall(N/A-Spec, ( member(P, Ps), hornguard:hg_allow(P, N/A),
                        hornguard:hg_any_meta_spec(N/A, Spec) ), Meta0),
    sort(Meta0, Meta),
    findall(N/A, ( hornguard:hg_pinned(_, N/A0), ( integer(A0) -> A = A0 ; between(0, 3, A) ) ), Pinned0),
    sort(Pinned0, Pinned).

data_value(a).
data_value(1).
data_value(2.5).
data_value("s").
data_value([a, b]).
data_value([]).
data_value(f(x)).
data_value(_).

gen_goal(D, Pure, Meta, Pinned, T) :-
    random_between(1, 100, R),
    (   D >= 4 -> gen_leaf(Pure, Pinned, T)
    ;   R =< 40 -> gen_leaf(Pure, Pinned, T)
    ;   R =< 60 -> gen_control(D, Pure, Meta, Pinned, T)
    ;   gen_meta(D, Pure, Meta, Pinned, T)
    ).

gen_leaf(Pure, Pinned, T) :-
    random_between(1, 100, R),
    (   R =< 88
    ->  random_member(N/A, Pure), gen_args(A, Args), T =.. [N|Args]
    ;   R =< 96
    ->  random_member(N/A, Pinned), gen_args(A, Args), T =.. [N|Args]
    ;   T = _
    ).

gen_args(A, Args) :-
    length(Args, A),
    maplist([X]>>( findall(V, data_value(V), Vs), random_member(X, Vs) ), Args).

gen_control(D, Pure, Meta, Pinned, T) :-
    D1 is D + 1,
    gen_goal(D1, Pure, Meta, Pinned, A),
    gen_goal(D1, Pure, Meta, Pinned, B),
    random_member(T, [ (A, B), (A ; B), (A -> B), (A *-> B), (A -> B ; true) ]).

gen_meta(D, Pure, Meta, Pinned, T) :-
    D1 is D + 1,
    random_member(N/_-Spec, Meta),
    Spec =.. [_|Modes],
    maplist(gen_mode_arg(D1, Pure, Meta, Pinned), Modes, Args),
    T =.. [N|Args].

gen_mode_arg(D, Pure, Meta, Pinned, 0, G) :- !, gen_goal(D, Pure, Meta, Pinned, G).
gen_mode_arg(D, Pure, Meta, Pinned, ^, G) :- !, gen_goal(D, Pure, Meta, Pinned, G).
gen_mode_arg(_, Pure, _, Pinned, K, C) :-
    integer(K), K > 0, !,
    % a closure: an allowed or pinned predicate missing its last K arguments
    random_between(1, 100, R),
    (   R =< 80 -> random_member(N/A, Pure) ; random_member(N/A, Pinned) ),
    Keep is max(0, A - K),
    gen_args(Keep, Args),
    C =.. [N|Args].
gen_mode_arg(_, _, _, _, _, V) :-
    findall(X, data_value(X), Vs), random_member(V, Vs).

		 /*******************************
		 *            REPORT            *
		 *******************************/

print_report(N, Seed, Report) :-
    aggregate_all(count, member(admitted(_), Report), NA),
    aggregate_all(count, member(refused(_, _, _), Report), NR),
    aggregate_all(count, member(needs(_, _), Report), NN),
    aggregate_all(count, member(composition_failure(_, _), Report), NF),
    forall(member(composition_failure(T, Ws), Report),
           ( format("COMPOSITION FAILURE~n  ~q~n", [T]),
             forall(member(wire(W, Dt), Ws),
                    ( term_to_atom(Dt, DA),
                      (   atom_length(DA, Len), Len > 160 -> sub_atom(DA, 0, 160, _, S) ; S = DA ),
                      format("    ~w: ~w~n", [W, S]) )) )),
    findall(Class, member(refused(_, Class, _), Report), Classes),
    msort(Classes, Sorted), clumped(Sorted, Counts),
    format("~d terms, seed ~w: ~d admitted and run clean, ~d refused ~q, ~d with needs, ~d composition failures~n",
           [N, Seed, NA, NR, Counts, NN, NF]).
