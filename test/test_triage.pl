:- module(test_triage, []).

%% Reading refusals by recurrence: the same refusal across many scopes is a
%% policy gap, one alone is worth a look, and the report says which is which.

:- use_module(library(plunit)).
:- use_module(library(lists)).
:- use_module('../tools/triage').

shadow(Ind, refused(permission_error(modify, static_procedure, Ind), shadowing, head(trusted))).
probe(G, refused(permission_error(execute, goal, G), capability_probe, pinned(process))).
nested(G, D, refused(permission_error(execute, goal, G), escape_attempt, pinned(process) + depth(D))).

:- begin_tests(triage).

test(recurring_across_scopes_comes_first_and_is_named_a_policy_gap_shape,
     [true(Groups = [group(recurring, shadowing, head(trusted), attribute/3, 4, 3)|_])]) :-
    shadow(attribute/3, S), probe(shell(x), P),
    triage([ns1-S, ns2-S, ns3-S, ns3-S, ns3-P], Groups).

test(one_scope_is_isolated, [true(memberchk(group(isolated, capability_probe, pinned(process), shell/1, 1, 1), Groups))]) :-
    shadow(attribute/3, S), probe(shell(x), P),
    triage([ns1-S, ns2-S, ns3-S, ns3-P], Groups).

test(the_threshold_is_an_option, [true(( Two = [group(recurring, _, _, _, _, 2)], Def = [group(isolated, _, _, _, _, 2)] ))]) :-
    shadow(relation/3, S),
    triage([a-S, b-S], [threshold(2)], Two),
    triage([a-S, b-S], Def).

test(depth_does_not_split_a_group, [true(Groups = [group(_, escape_attempt, pinned(process), shell/1, 3, 3)])]) :-
    nested(shell(x), 1, A), nested(shell(x), 2, B), nested(shell(x), 3, C),
    triage([a-A, b-B, c-C], Groups).

test(admits_are_ignored, [true(Groups == [])]) :-
    triage([a-admit, b-admit_needs([profile(swi)])], Groups).

test(a_reason_without_an_indicator_groups_under_none, [true(Groups = [group(_, escape_attempt, unbound_goal, none, 1, 1)])]) :-
    triage([a-refused(instantiation_error, escape_attempt, unbound_goal)], Groups).

test(the_report_prints, [true(sub_string(Out, _, _, _, "recurring"))]) :-
    shadow(attribute/3, S),
    triage([a-S, b-S, c-S], Groups),
    with_output_to(string(Out), print_triage(Groups)).

:- end_tests(triage).
