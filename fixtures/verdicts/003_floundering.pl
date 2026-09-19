%% Floundering fixtures. floundering/3 checks the pure analysis (the list of
%% offending negated goals, in body order); clause_verdict and verdict
%% fixtures check the refusal under the default strict_negation(true).

%% Bound by the head or an earlier positive goal: fine.
floundering(fl_head_bound,
    (orphan(X) :- person(X), \+ parent(_, X)), []).
floundering(fl_earlier_bound,
    (lonely(X) :- person(X), person(Y), \+ knows(X, Y)), []).

%% Occurs only inside the negation: existential, fine.
floundering(fl_existential,
    (childless(X) :- person(X), \+ parent(X, _)), []).
floundering(fl_existential_named,
    (childless(X) :- person(X), \+ parent(X, Kid)), []).

%% Introduced by the negation and used later: the bug.
floundering(fl_used_after,
    (bad(X) :- \+ parent(Y, X), older(Y, X)), [\+ parent(Y, X)]).
floundering(fl_not_used_after,
    (bad(X) :- not(parent(Y, X)), older(Y, X)), [not(parent(Y, X))]).
%% Two negations sharing a variable that nothing positive uses are two
%% independent existentials: fine.
floundering(fl_two_negations_share,
    (ok :- \+ q(X), \+ r(X)), []).
floundering(fl_both_reported,
    (bad :- \+ q(X), \+ r(Y), s(X), t(Y)), [\+ q(X), \+ r(Y)]).

%% A goal read as a headless body.
floundering(fl_query_bad,
    (\+ member(X, [a]), atom(X)), [\+ member(X, [a])]).
floundering(fl_query_existential,
    \+ member(_, [a]), []).

%% Aggregation binds only its result: template and goal variables are
%% local, so a later negation over them is not bound.
floundering(fl_aggregate_locals_unbound,
    (c(N) :- findall(X, p(X), L), \+ q(X), r(X), length(L, N)), [\+ q(X)]).
floundering(fl_aggregate_result_bound,
    (c(N) :- findall(X, p(X), L), \+ empty(L), length(L, N)), []).
floundering(fl_forall_binds_nothing,
    (d :- forall(p(X), q(X)), \+ r(X), s(X)), [\+ r(X)]).

%% Disjunction is read permissively: bound in any earlier branch counts.
floundering(fl_disjunction_permissive,
    (d(X) :- ( p(X) ; q(Y) ), \+ r(Y), s(Y)), []).

%% Facts have no body.
floundering(fl_fact, p(a), []).

%% Refusal under the default policy, and its place in the order: capability
%% first, then floundering, then stratification.
clause_verdict(fl_refused,            iso, [iso],
    (bad(X) :- \+ atom_length(Y, X), atom(Y)),
    refused(semantics, floundering(\+ atom_length(_, _)))).
clause_verdict(fl_capability_first,   iso, [iso],
    (bad(X) :- \+ atom_length(Y, X), current_prolog_flag(Y, _)),
    refused(capability_probe, pinned(flags_ops))).
verdict(fl_query_refused,             iso, [iso, prologue],
    (\+ member(X, [a]), atom(X)),
    refused(semantics, floundering(\+ member(_, [a])))).
verdict(fl_query_existential_admit,   iso, [iso, prologue],
    \+ member(_, [a]),
    admit).
program_verdict(fl_before_strata,     iso, [iso],
    [ (p(X) :- \+ q(Y), r(X, Y)), (r(_, _) :- \+ p(_)), q(1) ],
    refused(semantics, floundering(\+ q(_)))).

%% A later occurrence inside another negation or inside an aggregation's
%% goal is a fresh local scope, not a use of the negated goal's variable.
%% Found by judging a production puzzle solver: the same name for a local
%% in two consecutive \+ and a forall is ordinary Prolog.
floundering(fl_later_local_scopes_not_uses,
    (possible(A, B, C, D, E) :-
        cell(A, B, C, 0),
        between(1, E, D),
        \+ ( between(1, E, F), F \== C, cell(A, B, F, D) ),
        \+ ( between(1, E, G), G \== B, cell(A, G, C, D) ),
        forall(greater(B, C, G, F), ( cell(A, G, F, H), ( H == 0 ; D > H ) ))),
    []).
floundering(fl_later_positive_use_still_flagged,
    (bad(A) :- \+ p(F, A), \+ q(F), r(F)),
    [\+ p(F, A), \+ q(F)]).
floundering(fl_aggregate_result_is_a_use,
    (bad(L) :- \+ p(X), findall(Y, q(X, Y), L)),
    []).
