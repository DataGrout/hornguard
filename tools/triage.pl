:- module(hornguard_triage,
          [ triage/2,                 % +ScopedRefusals, -Groups
            triage/3,                 % +ScopedRefusals, +Options, -Groups
            print_triage/1,           % +Groups
            triage_file/1             % +File of Scope-Verdict terms; prints
          ]).

%% Reading refusals by recurrence.
%%
%% The judge names the shape it saw and never the author's intent, because
%% at the boundary a mistaken agent, an injected one and an attacker look
%% the same. A host can read intent from what the judge cannot see: how
%% often the same refusal recurs, and across how many scopes. One clause
%% refused for shadowing a trusted head in one namespace is worth a look.
%% The same head refused across most of a host's namespaces is a policy
%% gap, so far always a host table authors legitimately fill that wanted
%% author_defines/1.
%%
%% triage/2 takes refusals paired with the scope each came from (a
%% namespace, a tenant, a file) and returns one group per class, rule shape
%% and indicator, with how many refusals and how many distinct scopes it
%% covers, marked `recurring` when it spans at least the threshold of scopes
%% (default 3) and `isolated` otherwise, recurring first.
%%
%%   ?- triage([ns1-refused(permission_error(modify, static_procedure, attribute/3), shadowing, head(trusted)),
%%              ns2-refused(permission_error(modify, static_procedure, attribute/3), shadowing, head(trusted)),
%%              ns2-refused(permission_error(execute, goal, shell/1), capability_probe, pinned(process))], G).
%%
%% A census or a shadow in a host is expected to feed this before anyone
%% reads a refusal as an attack. `make triage FILE=refusals.pl` reads a
%% file of `Scope-Verdict.` terms and prints the report.

:- use_module(library(lists)).
:- use_module(library(apply)).
:- use_module(library(pairs)).
:- use_module(library(aggregate)).

triage(Scoped, Groups) :-
    triage(Scoped, [], Groups).

%!  triage(+ScopedRefusals, +Options, -Groups) is det.
%
%   ScopedRefusals is a list of Scope-Verdict where Verdict is
%   refused(Reason, Class, Rule); other verdicts are ignored. Options:
%   threshold(N), the number of distinct scopes at which a group is
%   `recurring` (default 3).
%
%   Groups is a list of
%     group(Standing, Class, RuleShape, Indicator, Refusals, Scopes)
%   with Standing `recurring` or `isolated`, sorted recurring first and by
%   scopes descending within.

triage(Scoped, Options, Groups) :-
    must_be(list, Scoped),
    (   memberchk(threshold(T), Options) -> must_be(positive_integer, T) ; T = 3 ),
    findall(key(Class, Shape, Ind)-Scope,
            ( member(Scope-refused(Reason, Class, Rule), Scoped),
              rule_shape(Rule, Shape),
              reason_indicator(Reason, Ind) ),
            Keyed0),
    keysort(Keyed0, Keyed),
    group_pairs_by_key(Keyed, ByKey),
    findall(Group,
            ( member(key(Class, Shape, Ind)-Scopes0, ByKey),
              length(Scopes0, NRef),
              sort(Scopes0, Scopes), length(Scopes, NSc),
              ( NSc >= T -> Standing = recurring ; Standing = isolated ),
              Group = group(Standing, Class, Shape, Ind, NRef, NSc) ),
            Groups0),
    predsort(by_standing_then_scopes, Groups0, Groups).

by_standing_then_scopes(Order, group(S1, C1, R1, I1, N1, K1), group(S2, C2, R2, I2, N2, K2)) :-
    standing_rank(S1, A), standing_rank(S2, B),
    compare(O1, A, B),
    (   O1 \== (=) -> Order = O1
    ;   compare(O2, K2, K1), O2 \== (=) -> Order = O2
    ;   compare(O3, N2, N1), O3 \== (=) -> Order = O3
    ;   compare(Order, t(C1, R1, I1), t(C2, R2, I2))
    ).

standing_rank(recurring, 0).
standing_rank(isolated, 1).

%   Collapse a rule to the shape counts group by: depth is per occurrence.
rule_shape(Rule + depth(_), Shape) :- !, rule_shape(Rule, Shape).
rule_shape(unstratified(_, _), unstratified) :- !.
rule_shape(floundering(_), floundering) :- !.
rule_shape(meta_spec(_), meta_spec) :- !.
rule_shape(Rule, Rule).

%   The indicator the reason names, when it names one.
reason_indicator(permission_error(_, _, Ind), Ind) :- indicator(Ind), !.
reason_indicator(permission_error(_, _, G), N/A) :- callable(G), !, functor(G, N, A).
reason_indicator(existence_error(_, Ind), Ind) :- indicator(Ind), !.
reason_indicator(_, none).

indicator(N/A) :- atom(N), integer(A).

%!  print_triage(+Groups) is det.

print_triage(Groups) :-
    (   Groups == []
    ->  format("no refusals~n")
    ;   format("~w~t~12|~w~t~30|~w~t~62|~w~t~92|~w~t~102|~w~n",
               ['standing', 'class', 'rule', 'indicator', 'refusals', 'scopes']),
        forall(member(group(S, C, R, I, N, K), Groups),
               format("~w~t~12|~w~t~30|~q~t~62|~q~t~92|~d~t~102|~d~n", [S, C, R, I, N, K])),
        aggregate_all(count, member(group(recurring, _, _, _, _, _), Groups), NR),
        length(Groups, NG),
        format("~n~d groups, ~d recurring. A recurring shadowing group is usually a host table that wants author_defines.~n", [NG, NR])
    ).

%!  triage_file(+File) is det.
%
%   File holds Scope-Verdict terms, one per clause. Reads them all and prints.

triage_file(File) :-
    setup_call_cleanup(open(File, read, In), read_terms(In, Scoped), close(In)),
    triage(Scoped, Groups),
    print_triage(Groups).

read_terms(In, Ts) :-
    read_term(In, T, []),
    (   T == end_of_file -> Ts = []
    ;   Ts = [T|Rest], read_terms(In, Rest)
    ).
