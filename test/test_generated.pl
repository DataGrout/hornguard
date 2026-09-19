:- module(test_generated, []).

%% Generated terms. A seeded random generator builds goals and clauses from
%% a vocabulary of pure goals, pinned goals, meta wrappers and control
%% constructs, remembering where it put each pinned goal. The properties
%% below must hold for every generated term; they state things no hand-
%% written fixture can state exhaustively.

:- use_module(library(plunit)).
:- use_module(library(lists)).
:- use_module(library(apply)).
:- use_module(library(random)).
:- use_module('../prolog/hornguard').

:- dynamic gen/3.              % Id, Term, Facts (list of what the generator did)

n_terms(400).
profiles([iso, prologue, swi_aggregate]).

generate_all :-
    retractall(gen(_, _, _)),
    set_random(seed(20260918)),
    n_terms(N),
    forall(between(1, N, I),
           ( gen_goal(0, T, Facts),
             assertz(gen(I, T, Facts)) )).

%   gen_goal(+Depth, -Term, -Facts). Facts is a list of
%   pinned(Depth) | unbound | data_pinned, one per leaf of that kind.
gen_goal(D, T, Facts) :-
    random_between(1, 100, R),
    (   D >= 4 -> gen_leaf(T, Facts)
    ;   R =< 35 -> gen_leaf(T, Facts)
    ;   R =< 60 -> gen_control(D, T, Facts)
    ;   gen_meta(D, T, Facts)
    ).

gen_leaf(T, Facts) :-
    random_between(1, 100, R),
    (   R =< 55 -> pure_goal(T), Facts = []
    ;   R =< 80 -> pinned_goal(T), Facts = [pinned]
    ;   R =< 90 -> pinned_goal(P), T = (_ = P), Facts = [data_pinned]
    ;   T = _, Facts = [unbound]
    ).

pure_goal(G) :-
    random_member(G, [ atom(a), atom_length(abc, _), _ = f(_), 1 < 2, true,
                       member(_, [a, b]), length([a], _), atom_codes(a, _),
                       X is 1 + 1, X > 0, copy_term(f(_), _), sort([b, a], _),
                       aggregate_all(count, atom(a), _) ]).

pinned_goal(G) :-
    random_member(G, [ current_prolog_flag(home, _), shell(x), assertz(f),
                       open(f, read, _), halt, current_predicate(_),
                       nb_setval(k, v), consult(f), getenv(h, _), format("~w", [x]) ]).

gen_control(D, T, Facts) :-
    D1 is D + 1,
    gen_goal(D1, A, FA), gen_goal(D1, B, FB),
    append(FA, FB, Facts),
    random_member(T, [ (A, B), (A ; B), (A -> B), (A *-> B) ]).

gen_meta(D, T, Facts) :-
    D1 is D + 1,
    gen_goal(D1, G, F0),
    maplist(deepen, F0, Facts),
    random_member(T, [ findall(_, G, _), forall(G, true), forall(true, G), \+ G, not(G),
                       once(G), catch(G, _, true), catch(true, _, G), call(G),
                       setof(_, G, _), aggregate_all(count, G, _), ignore(G) ]).

deepen(pinned, pinned).
deepen(unbound, unbound).
deepen(data_pinned, data_pinned).

has(Facts, What) :- memberchk(What, Facts).

:- initialization(generate_all).

:- begin_tests(generated).

test(pinned_in_call_position_is_always_refused,
     [ forall(( gen(_, T, F), has(F, pinned) )), true(V = refused(_, _, _)) ]) :-
    profiles(Ps),
    hornguard_admit(iso, Ps, T, V).

test(pinned_refusal_is_a_pinned_or_unbound_rule,
     [ forall(( gen(_, T, F), has(F, pinned) )), true(Ok == yes) ]) :-
    profiles(Ps),
    hornguard_admit(iso, Ps, T, V),
    (   ( V = refused(_, _, pinned(_)) ; V = refused(_, _, pinned(_) + depth(_))
        ; V = refused(_, _, unbound_goal) )
    ->  Ok = yes
    ;   Ok = V
    ).

test(clean_terms_are_never_refused,
     [ forall(( gen(_, T, F), \+ has(F, pinned), \+ has(F, unbound) )), true(Ok == yes) ]) :-
    profiles(Ps),
    hornguard_admit(iso, Ps, T, V),
    ( ( V == admit ; V = admit_needs(_) ) -> Ok = yes ; Ok = V ).

test(pinned_functor_in_data_position_alone_is_admitted,
     [ forall(( gen(_, T, F), has(F, data_pinned), \+ has(F, pinned), \+ has(F, unbound) )),
       true(Ok == yes) ]) :-
    profiles(Ps),
    hornguard_admit(iso, Ps, T, V),
    ( ( V == admit ; V = admit_needs(_) ) -> Ok = yes ; Ok = V ).

test(unbound_call_position_is_refused_when_nothing_pinned_precedes,
     [ forall(( gen(_, T, F), has(F, unbound) )), true(V = refused(_, _, _)) ]) :-
    profiles(Ps),
    hornguard_admit(iso, Ps, T, V).

test(refusal_is_monotonic_under_profile_subsets,
     [ forall(( gen(_, T, _), profiles(Ps), hornguard_admit(iso, Ps, T, refused(_, _, _)) )),
       true(V = refused(_, _, _)) ]) :-
    hornguard_admit(iso, [], T, V).

test(judge_never_binds_its_input, [ forall(gen(_, T, _)), true(Same == true) ]) :-
    profiles(Ps),
    copy_term(T, Before),
    hornguard_admit(iso, Ps, T, _),
    ( T =@= Before -> Same = true ; Same = false ).

test(judge_is_deterministic, [ forall(gen(_, T, _)), true(V1 =@= V2) ]) :-
    profiles(Ps),
    hornguard_admit(iso, Ps, T, V1),
    hornguard_admit(iso, Ps, T, V2).

test(swi_backend_agrees_on_refusal,
     [ forall(( gen(_, T, _), profiles(Ps), hornguard_admit(iso, Ps, T, refused(_, C, R)) )),
       true(V = refused(_, C, R)) ]) :-
    profiles(Ps),
    hornguard_admit(swi, Ps, T, V).

test(as_clause_body_same_verdict_class,
     [ forall(gen(_, T, _)), true(Same == true) ]) :-
    profiles(Ps),
    hornguard_admit(iso, Ps, T, VG),
    hornguard_admit_clause(iso, Ps, (h(_) :- T), [strict_negation(false)], VC),
    (   (   ( VG = refused(_, Cg, _), VC = refused(_, Cc, _), Cg == Cc )
        ;   ( ( VG == admit ; VG = admit_needs(_) ), ( VC == admit ; VC = admit_needs(_) ) )
        )
    ->  Same = true
    ;   Same = VG-VC
    ).

:- end_tests(generated).
