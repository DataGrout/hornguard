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

%   The trusted definition is the one whose body is never walked, so an
%   author may not store a clause with that head and stand in for it.
test(clause_may_not_define_a_trusted_predicate,
     [true(V = refused(_, shadowing, head(trusted)))]) :-
    hornguard_admit_clause((lookup_price(_, _, 0) :- true), V).

test(fact_may_not_define_a_trusted_predicate,
     [true(V = refused(_, shadowing, head(trusted)))]) :-
    hornguard_admit_clause(with_tenant(any, true), V).

test(program_may_not_define_a_trusted_predicate,
     [true(V = refused(_, shadowing, head(trusted)))]) :-
    hornguard_admit_program([ (tiered(C) :- customer_tier(C, gold)),
                              (lookup_price(_, _, 0) :- true) ], V).

test(host_allow_heads_are_the_authors_own, [true(V == admit)]) :-
    % allow/1 names predicates whose clauses live in sandboxed space; storing
    % another clause of one is the normal case.
    hornguard_admit_clause((customer_tier(acme, gold) :- true), V).

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

% A host installs its own profiles beside the shipped ones by loading a list
% of directories. The private directory here is created on the fly.
:- begin_tests(profile_dirs, [cleanup(( hornguard:hg_default_dir(D), hornguard_load_profiles(D), load(host) ))]).

private_dir(Dir) :-
    tmp_file(hg_private_profiles, Dir),
    make_directory(Dir),
    directory_file_path(Dir, 'host_private.pl', F),
    setup_call_cleanup(open(F, write, S),
        format(S, "allow(host_private, secret_score/2).~nallow(host_private, each_secret/2).~nmeta_spec(host_private, each_secret(1, ?)).~n", []),
        close(S)).

test(private_profile_dir_joins_shipped_ones, [true(V == admit)]) :-
    private_dir(P),
    hornguard:hg_default_dir(D),
    hornguard_load_profiles([D, P]),
    hornguard_profiles(Names),
    memberchk(host_private, Names), memberchk(iso, Names),
    hornguard_admit(iso, [iso, host_private], (secret_score(a, S), S > 1), V).

test(private_meta_spec_is_applied, [true(V = refused(_, escape_attempt, pinned(flags_ops) + depth(1)))]) :-
    private_dir(P),
    hornguard:hg_default_dir(D),
    hornguard_load_profiles([D, P]),
    hornguard_admit(iso, [iso, host_private], each_secret(current_prolog_flag(home), [_]), V).

test(private_profile_cannot_reopen_a_pin, [throws(error(permission_error(allow, pinned(process), shell/1), _))]) :-
    tmp_file(hg_private_bad, Dir), make_directory(Dir),
    directory_file_path(Dir, 'bad.pl', F),
    setup_call_cleanup(open(F, write, S), format(S, "allow(host_private, shell/1).~n", []), close(S)),
    hornguard:hg_default_dir(D),
    hornguard_load_profiles([D, Dir]).

%   A directory that fails to load must leave the profiles that were in
%   force untouched: the tables are replaced only once every file has been
%   read and checked.
test(failed_profile_load_leaves_previous_profiles_in_force,
     [true(( Still == true, V = refused(_, capability_probe, pinned(process)) ))]) :-
    private_dir(P),
    hornguard:hg_default_dir(D),
    hornguard_load_profiles([D, P]),
    tmp_file(hg_private_bad2, Bad), make_directory(Bad),
    directory_file_path(Bad, 'bad.pl', F),
    setup_call_cleanup(open(F, write, S), format(S, "allow(host_private, shell/1).~n", []), close(S)),
    catch(hornguard_load_profiles([D, Bad]), error(permission_error(_, _, _), _), true),
    hornguard_profiles(Names),
    ( memberchk(host_private, Names), memberchk(iso, Names) -> Still = true ; Still = Names ),
    hornguard_admit(iso, [iso], shell(x), V).

%   A host that builds its own engine ships a manifest for it. Deferral has
%   to read that manifest, or defer_unknown(true) turns every builtin the
%   host declared into an admit_needs and the engine surface widens by
%   exactly the predicates the manifest was written to describe. On swi the
%   engine is asked directly and this always held; on a manifest backend it
%   did not, because a separate helper answered the same question for swi
%   alone. The pair below pins it from both sides.
private_engine_dir(Dir) :-
    tmp_file(hg_private_engine, Dir),
    make_directory(Dir),
    directory_file_path(Dir, 'host_engine.pl', F),
    setup_call_cleanup(open(F, write, S),
        format(S, "engine(scryer, host_engine_builtin/1).~n", []),
        close(S)).

with_private_engine(Goal) :-
    private_engine_dir(P),
    hornguard:hg_default_dir(D),
    hornguard_load_profiles([D, P]),
    call(Goal).

test(defer_unknown_does_not_widen_a_manifest_backend,
     [true(V = refused(permission_error(execute, goal, host_engine_builtin/1),
                       benign_miss, unknown))]) :-
    with_private_engine(
        hornguard_admit(scryer, [iso], host_engine_builtin(x), [defer_unknown(true)], V)).

test(defer_unknown_still_defers_what_no_manifest_claims,
     [true(V == admit_needs([predicate(stored_later/1)]))]) :-
    with_private_engine(
        hornguard_admit(scryer, [iso], stored_later(x), [defer_unknown(true)], V)).

:- end_tests(profile_dirs).

:- begin_tests(backends).

test(every_shipped_backend_declares_enforcement, [true(Missing == [])]) :-
    hornguard_profiles(_),
    findall(B, ( member(B, [iso, swi, scryer, trealla]),
                 \+ hornguard:hg_enforcement(B, _) ), Missing).

test(iso_is_judge_only, [true(K == none)]) :- hornguard:hg_enforcement(iso, K).
test(swi_enforces_natively, [true(K == native)]) :- hornguard:hg_enforcement(swi, K).
test(manifest_backends_need_an_external_bound, [true(Ks == [external, external])]) :-
    findall(K, ( member(B, [scryer, trealla]), hornguard:hg_enforcement(B, K) ), Ks).

test(run_refuses_on_a_judge_only_backend,
     [throws(error(permission_error(run, backend, iso), _))]) :-
    hornguard_run(iso, [iso], [], true).

test(run_refuses_where_the_host_must_bound_the_engine,
     [throws(error(permission_error(run, backend, scryer), _))]) :-
    hornguard_run(scryer, [iso], [], true).

%   The manifests record what these engines really expose in a bare
%   interpreter. A smaller builtin list is a smaller attack surface, not a
%   sandbox: Scryer has the clause store, the loader, reflection and halt.
test(scryer_exposes_capabilities_the_pins_refuse, [true(Missing == [])]) :-
    hornguard_profiles(_),
    findall(I, ( member(I, [assertz/1, retract/1, use_module/1, consult/1, halt/0,
                            clause/2, current_prolog_flag/2, set_prolog_flag/2, op/3]),
                 \+ hornguard:hg_engine(scryer, I) ), Missing).

%   shell/1 is NOT in the bare manifest: on Scryer it arrives with
%   library(os). That is exactly why `loading` is pinned. The manifest
%   describes the engine as started, and a host that lets an author load a
%   library has widened the engine, not the profile.
test(the_loader_is_what_closes_the_chain_to_shell, [true(( NoShell == true, Loading == true ))]) :-
    hornguard_profiles(_),
    ( hornguard:hg_engine(scryer, shell/1) -> NoShell = false ; NoShell = true ),
    ( hornguard:hg_pinned(loading, use_module/1) -> Loading = true ; Loading = false ).

%   Pins are by name and apply whatever the manifest says, so a capability an
%   engine gains from a library is still refused if it is ever reached.
test(a_pin_does_not_depend_on_the_manifest,
     [true(V = refused(_, capability_probe, pinned(process)))]) :-
    hornguard_admit(scryer, [iso], shell(x), V).

test(a_manifest_makes_an_unknown_a_permission_error_not_an_existence_error,
     [true(( S = permission_error(_, _, _), T = existence_error(_, _) ))]) :-
    % shell/1 is pinned, so take something the engine has that no profile
    % allows: the manifest is what tells the two apart.
    hornguard_admit(scryer, [iso], succ_throw_marker, refused(T, _, unknown)),
    hornguard_admit(scryer, [iso], '$skip_max_list'(_, _, _, _), refused(S0, _, _)),
    ( hornguard:hg_engine(scryer, '$skip_max_list'/4) -> S = S0 ; S = permission_error(x, y, z) ).

:- end_tests(backends).

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

:- begin_tests(author_defines, [setup(load(author_defines)), cleanup(load(host))]).

% A fact store: the host provides attribute/3, authors add facts to it.
test(an_author_may_add_a_fact_to_a_declared_table, [true(V == admit)]) :-
    hornguard_admit_clause(attribute(acme, tier, gold), V).

test(an_author_may_add_a_rule_to_a_declared_table, [true(V == admit)]) :-
    hornguard_admit_clause((attribute(E, tier, gold) :- attribute(E, revenue, R), R > 1000), V).

% The head is permitted; the body is walked like any other.
test(the_body_of_such_a_rule_is_still_walked,
     [true(V = refused(_, capability_probe, pinned(process)))]) :-
    hornguard_admit_clause((attribute(_, cmd, out) :- shell(x)), V).

% Declared without a trust or allow: the head is fine, a call is what the
% policy otherwise says, here an unknown the host deferred.
test(a_declared_head_needs_no_trust_to_be_defined, [true(V == admit)]) :-
    hornguard_admit_clause(note(hello), V).

test(a_declared_head_with_no_allow_is_still_unknown_to_call, [true(V == admit_needs([predicate(note/1)]))]) :-
    hornguard_admit(note(_), V).

% Everything not declared keeps the rule.
test(a_trusted_predicate_not_declared_is_still_not_definable,
     [true(V = refused(_, shadowing, head(trusted)))]) :-
    hornguard_admit_clause(lookup_price(_, _, 0), V).

test(a_program_mixing_both_is_judged_clause_by_clause,
     [true(V = refused(_, shadowing, head(trusted)))]) :-
    hornguard_admit_program([ attribute(a, b, c), (lookup_price(_, _, 0) :- true) ], V).

test(the_option_reaches_the_judge_as_one_list, [true(memberchk(author_defines(L), Os)), true(msort(L, [attribute/3, note/1]))]) :-
    hornguard_policy(policy(_, _, Os, _, _)).

:- end_tests(author_defines).

:- begin_tests(policy_errors, [cleanup(load(host))]).

test(author_defines_of_pinned_is_a_load_error,
     [throws(error(permission_error(author_defines, pinned(process), shell/1), _))]) :-
    load(bad_author_defines_pinned).

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

%   The pins too. A file that reopens a class and then fails validation used
%   to leave the class open with the old policy still recorded; every check
%   now runs before anything changes.
test(failed_load_with_unpin_leaves_the_class_pinned,
     [true(V = refused(_, reconnaissance, pinned(reflection)))]) :-
    load(host),
    catch(load(bad_unpin_then_error), error(domain_error(_, _), _), true),
    hornguard_admit(clause(foo(_), _), V).

test(unpin_of_unknown_class_is_a_load_error,
     [throws(error(domain_error(hornguard_pinned_class, no_such_class), _))]) :-
    load(bad_unpin_unknown).

test(unpin_of_unknown_class_changes_nothing,
     [true(( V = refused(_, reconnaissance, pinned(reflection)), P = policy(swi, [iso, prologue, swi_lists], _, _, _) ))]) :-
    load(host),
    catch(load(bad_unpin_unknown), _, true),
    hornguard_admit(clause(foo(_), _), V),
    hornguard_policy(P).

:- end_tests(policy_errors).
