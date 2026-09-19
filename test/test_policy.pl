:- module(test_policy, []).

%% Policy files: what a host adds on top of the profiles, and what a policy
%% may never do.

:- use_module(library(plunit)).
:- use_module(library(lists)).
:- use_module('../prolog/hornguard').

:- dynamic policy_dir/1.
:- prolog_load_context(directory, Dir),
   atomic_list_concat([Dir, '/policies'], P),
   retractall(policy_dir(_)),
   assertz(policy_dir(P)).

policy(Name, Path) :-
    policy_dir(D),
    atomic_list_concat([D, '/', Name, '.pl'], Path).

load(Name) :-
    policy(Name, Path),
    hornguard_load_policy(Path).

:- begin_tests(policy_file, [setup(load(host)), cleanup(load(host))]).

test(loaded_shape, [true(P == policy(swi, [iso, prologue, swi_lists],
                                      [defer_unknown(true), strict_negation(true)],
                                      [region_of/2, customer_tier/2],
                                      [with_tenant/2-with_tenant(?, 0), lookup_price/3-none]))]) :-
    hornguard_policy(P).

test(host_allow_admits, [true(V == admit)]) :-
    hornguard_admit((customer_tier(C, T), region_of(C, _), atom(T)), V).

test(trusted_without_spec_admits, [true(V == admit)]) :-
    hornguard_admit(lookup_price(sku1, _, _), V).

test(trusted_with_spec_judges_goal_arg, [true(V = refused(_, escape_attempt, pinned(flags_ops) + depth(1)))]) :-
    hornguard_admit(with_tenant(t1, current_prolog_flag(home, _)), V).

test(trusted_body_is_not_walked, [true(V == admit)]) :-
    % lookup_price/3 is trusted: whatever its clauses do is the host's business.
    hornguard_admit(lookup_price(a, b, c), V).

test(defer_unknown_from_policy, [true(V == admit_needs([predicate(later/1)]))]) :-
    hornguard_admit_clause((first(X) :- later(X)), V).

test(profile_not_in_force_is_a_need, [true(V == admit_needs([profile(swi)]))]) :-
    hornguard_admit(string_concat(a, b, _), V).

test(strict_negation_from_policy, [true(V = refused(_, semantics, floundering(_)))]) :-
    hornguard_admit_clause((bad(X) :- \+ atom_length(Y, X), atom(Y)), V).

test(pinned_still_pinned_under_host_policy, [true(V = refused(_, capability_probe, pinned(process)))]) :-
    hornguard_admit(shell('true'), V).

test(program_under_policy, [true(V == admit)]) :-
    hornguard_admit_program([ (tiered(C) :- customer_tier(C, gold)),
                              (gold_count(N) :- findall(C, tiered(C), Cs), length(Cs, N)) ], V).

:- end_tests(policy_file).

:- begin_tests(policy_unpin, [cleanup(load(host))]).

test(unpin_warns_and_admits, [true(V == admit)]) :-
    % The warning is printed via print_message; we check the effect.
    load(unpin_reflection),
    hornguard_admit(clause(foo(_), _), V).

test(unpin_is_undone_by_next_policy, [true(V = refused(_, reconnaissance, pinned(reflection)))]) :-
    load(unpin_reflection),
    load(host),
    hornguard_admit(clause(foo(_), _), V).

:- end_tests(policy_unpin).

:- begin_tests(policy_errors, [cleanup(load(host))]).

test(allow_of_pinned_is_a_load_error, [throws(error(permission_error(allow, pinned(process), shell/1), _))]) :-
    load(bad_allow_pinned).

test(trust_spec_arity_mismatch, [throws(error(domain_error(hornguard_policy, trust_spec(_, _)), _))]) :-
    load(bad_trust_spec).

test(unknown_profile, [throws(error(domain_error(hornguard_policy, unknown_profile(no_such_profile)), _))]) :-
    load(bad_unknown_profile).

test(unknown_term, [throws(error(domain_error(hornguard_policy_term, allow_everything(please)), _))]) :-
    load(bad_term).

test(failed_load_leaves_previous_policy, [true(P = policy(swi, [iso, prologue, swi_lists], _, _, _))]) :-
    load(host),
    catch(load(bad_term), _, true),
    hornguard_policy(P).

:- end_tests(policy_errors).
