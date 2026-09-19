%% Stratification fixtures. stratification/3 checks the pure analysis;
%% program_verdict/5 checks it composed with clause admission.
%%
%% Strata are listed lowest first; indicators inside a stratum are in
%% standard order. Predicates not defined in the program are base relations
%% and do not appear.

%% Positive recursion is one stratum.
stratification(strat_transitive,
    [ edge(a, b), edge(b, c),
      (path(X, Y) :- edge(X, Y)),
      (path(X, Y) :- edge(X, Z), path(Z, Y)) ],
    stratified([[edge/2, path/2]])).

%% Negation over a lower stratum lifts the caller one level.
stratification(strat_negation_lifts,
    [ node(a), node(b), edge(a, b),
      (path(X, Y) :- edge(X, Y)),
      (path(X, Y) :- edge(X, Z), path(Z, Y)),
      (unreachable(X, Y) :- node(X), node(Y), \+ path(X, Y)) ],
    stratified([[edge/2, node/1, path/2], [unreachable/2]])).

%% not/1 is the same negation as \+.
stratification(strat_not_lifts,
    [ p(a), (q(X) :- not(p(X))) ],
    stratified([[p/1], [q/1]])).

%% Chains of negation give chains of strata.
stratification(strat_chain,
    [ a(1), (b(X) :- a(X), \+ c(X)), (c(X) :- a(X), \+ d(X)), d(1) ],
    stratified([[a/1, d/1], [c/1], [b/1]])).

%% Aggregation is stratified like negation: the caller sits above what it
%% collects.
stratification(strat_aggregate_lifts,
    [ edge(a, b), edge(a, c),
      (out_degree(X, N) :- findall(Y, edge(X, Y), L), length(L, N)) ],
    stratified([[edge/2], [out_degree/2]])).

%% Recursion through negation has no single intended model.
stratification(strat_negative_cycle,
    [ (p(X) :- q(X), \+ r(X)), (r(X) :- q(X), \+ p(X)), q(1) ],
    unstratified([p/1, r/1], p/1-r/1)).

stratification(strat_self_negation,
    [ (p :- \+ p) ],
    unstratified([p/0], p/0-p/0)).

%% Recursion through aggregation is the same problem.
stratification(strat_aggregate_cycle,
    [ (count(N) :- findall(X, count(X), L), length(L, N)) ],
    unstratified([count/1], count/1-count/1)).

%% A negative edge into a positive cycle taints the whole component.
stratification(strat_cycle_through_negation,
    [ (a(X) :- b(X)), (b(X) :- c(X)), (c(X) :- \+ a(X)) ],
    unstratified([a/1, b/1, c/1], c/1-a/1)).

%% Negation inside a meta-argument is still negation; positive
%% meta-arguments keep polarity.
stratification(strat_negation_in_meta,
    [ p(1), (q(L) :- findall(X, \+ p(X), L)) ],
    stratified([[p/1], [q/1]])).

stratification(strat_forall_is_negative,
    [ p(1), q(1), (all_q :- forall(p(X), q(X))) ],
    stratified([[p/1, q/1], [all_q/0]])).

%% Base relations and facts-only programs.
stratification(strat_facts_only,
    [ a(1), b(2) ],
    stratified([[a/1, b/1]])).

stratification(strat_empty, [], stratified([])).

%% Composed with admission: rules may call each other, capability refusals
%% come first, and an unstratified program is refused under `semantics`.
program_verdict(prog_admit_mutual,      iso, [iso],
    [ (even(0) :- true), (even(X) :- X > 0, Y is X - 1, odd(Y)),
      (odd(X) :- X > 0, Y is X - 1, even(Y)) ],
    admit).

program_verdict(prog_needs,             iso, [iso],
    [ (first(X) :- member(X, [a])) ],
    admit_needs([profile(prologue)])).

program_verdict(prog_capability_first,  iso, [iso],
    [ (p :- \+ p), (leak(V) :- current_prolog_flag(home, V)) ],
    refused(capability_probe, pinned(flags_ops))).

program_verdict(prog_unstratified,      iso, [iso],
    [ (p(X) :- q(X), \+ r(X)), (r(X) :- q(X), \+ p(X)), q(1) ],
    refused(semantics, unstratified([p/1, r/1], p/1-r/1))).

program_verdict(prog_directive,         iso, [iso],
    [ p(1), (:- initialization(true)) ],
    refused(capability_probe, directive)).
