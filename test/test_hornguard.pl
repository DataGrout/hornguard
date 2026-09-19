:- module(test_hornguard, []).

%% Fixture runner.
%%
%% Loads every .pl file under fixtures/verdicts and runs each verdict/5 and
%% clause_verdict/5 fact through the pack. A fixture's expected
%% refused(Class, Rule) matches a verdict refused(_Reason, Class, Rule); the
%% reason term is the host's business. Run with `make test` or
%%
%%     swipl -g run_tests -t halt test/test_hornguard.pl

:- use_module(library(plunit)).
:- use_module(library(lists)).
:- use_module('../prolog/hornguard').

:- dynamic fixture/6.          % Kind, Id, Backend, Profiles, Term, Expected
:- dynamic fixture_dir/1.

:- prolog_load_context(directory, Dir),
   atomic_list_concat([Dir, '/../fixtures/verdicts'], Rel),
   absolute_file_name(Rel, Abs),
   retractall(fixture_dir(_)),
   assertz(fixture_dir(Abs)).

%   Extra fixture directories, colon-separated, from HORNGUARD_FIXTURES_EXTRA.
%   A host keeps fixtures it does not publish — cases derived from its own
%   incidents — in its own directory and runs the same suite over both. The
%   public suite is the contract; an overlay only adds to it, and the
%   mutation harness is what decides whether a case belongs in the contract:
%   anything it needs to kill a mutant is structural and stays public.
extra_dirs(Dirs) :-
    (   getenv('HORNGUARD_FIXTURES_EXTRA', Spec)
    ->  split_string(Spec, ":", "", Parts),
        findall(D, ( member(P, Parts), P \== "", atom_string(D, P), exists_directory(D) ), Dirs)
    ;   Dirs = []
    ).

load_fixtures :-
    retractall(fixture(_, _, _, _, _, _)),
    fixture_dir(Dir),
    extra_dirs(Extra),
    forall(( member(D, [Dir|Extra]),
             directory_files(D, Es),
             include([E]>>file_name_extension(_, pl, E), Es, Fs0),
             msort(Fs0, Fs),
             member(F, Fs) ),
           ( directory_file_path(D, F, Path),
             load_fixture_file(Path) )).

load_fixture_file(Path) :-
    setup_call_cleanup(
        open(Path, read, In),
        read_fixture_terms(In, Path),
        close(In)).

read_fixture_terms(In, Path) :-
    read_term(In, Term, []),
    (   Term == end_of_file
    ->  true
    ;   accept_fixture(Term, Path),
        read_fixture_terms(In, Path)
    ).

accept_fixture(verdict(Id, B, P, T, E), _) :- !,
    assertz(fixture(goal, Id, B, P, T, E)).
accept_fixture(clause_verdict(Id, B, P, T, E), _) :- !,
    assertz(fixture(clause, Id, B, P, T, E)).
accept_fixture(program_verdict(Id, B, P, T, E), _) :- !,
    assertz(fixture(program, Id, B, P, T, E)).
accept_fixture(stratification(Id, T, E), _) :- !,
    assertz(fixture(strata, Id, iso, [], T, E)).
accept_fixture(floundering(Id, T, E), _) :- !,
    assertz(fixture(flounder, Id, iso, [], T, E)).
accept_fixture((:- _), _) :- !.
accept_fixture(Term, Path) :-
    throw(error(domain_error(hornguard_fixture_term, Term), context(Path, _))).

:- initialization(load_fixtures).

judge(goal, B, P, T, V)    :- hornguard_admit(B, P, T, V).
judge(clause, B, P, T, V)  :- hornguard_admit_clause(B, P, T, V).
judge(program, B, P, T, V) :- hornguard_admit_program(B, P, T, V).
judge(strata, _, _, T, V)  :- hornguard_stratification(T, V).
judge(flounder, _, _, T, V) :- hornguard_floundering(T, V).

matches(refused(Class, Rule), refused(_Reason, Class, Rule)) :- !.
matches(Expected, Expected).

:- begin_tests(fixtures).

test(verdict, [ forall(fixture(Kind, Id, B, P, T, E)),
                true(Ok == yes) ]) :-
    judge(Kind, B, P, T, V),
    (   matches(E, V)
    ->  Ok = yes
    ;   format(user_error, "~n  fixture ~w~n    expected ~q~n    got      ~q~n", [Id, E, V]),
        Ok = no
    ).

test(fixture_ids_unique) :-
    findall(Id, fixture(_, Id, _, _, _, _), Ids),
    msort(Ids, Sorted),
    length(Ids, N),
    length(Sorted, N),
    \+ ( append(_, [X, X|_], Sorted) ).

:- end_tests(fixtures).

:- begin_tests(policy).

test(profiles_loaded, [true(subset([iso, prologue, swi], Names))]) :-
    hornguard_profiles(Names).

test(monotonic_refusal, [ forall(( fixture(goal, _, B, P, T, refused(_, _)), P \== [] )),
                          true(V = refused(_, _, _)) ]) :-
    % Refused under P must stay refused under any subset; check the empty set.
    hornguard_admit(B, [], T, V).

test(strict_negation_default_refuses, [true(V = refused(_, semantics, floundering(_)))]) :-
    hornguard_admit_clause(iso, [iso], (bad(X) :- \+ atom_length(Y, X), atom(Y)), V).

test(strict_negation_false_admits, [true(V == admit)]) :-
    hornguard_admit_clause(iso, [iso], (bad(X) :- \+ q(Y, X), r(Y)),
                           [strict_negation(false), allow([q/2, r/1])], V).

test(strict_negation_false_still_reports, [true(Gs = [\+ q(_, _)])]) :-
    hornguard_floundering((bad(X) :- \+ q(Y, X), r(Y)), Gs).

% Hostile term shapes cannot be written as fixture facts (read_term cannot
% produce a cyclic term), so they live here.
test(cyclic_goal_refused, [true(V == refused(type_error(acyclic_term, cyclic), evasion, cyclic_term))]) :-
    X = (true, X),
    hornguard_admit(iso, [iso], X, V).

test(cyclic_meta_arg_refused, [true(V = refused(_, evasion, cyclic_term))]) :-
    G = findall(_, G, _),
    hornguard_admit(iso, [iso], G, V).

test(cyclic_clause_refused, [true(V = refused(_, evasion, cyclic_term))]) :-
    B = (true, B),
    hornguard_admit_clause(iso, [iso], (p :- B), V).

test(cyclic_program_refused, [true(V = refused(_, evasion, cyclic_term))]) :-
    B = (true, B),
    hornguard_admit_program(iso, [iso], [p(1), (q :- B)], V).

test(deep_conjunction_admitted, [true(V == admit)]) :-
    numlist(1, 100000, L),
    foldl([_, A, (true, A)]>>true, L, true, T),
    hornguard_admit(iso, [iso], T, V).

test(deep_negation_admitted, [true(V == admit)]) :-
    numlist(1, 100000, L),
    foldl([_, A, \+ A]>>true, L, true, T),
    hornguard_admit(iso, [iso], T, V).

test(attributed_var_does_not_fire, [true(V == admit)]) :-
    freeze(X, throw(coroutine_fired)),
    hornguard_admit(iso, [iso], atom(X), V).

test(partially_bound_verdict_fails_not_throws, [fail]) :-
    hornguard_admit(iso, [iso], call(_), admit).

test(partially_bound_verdict_matches, [true]) :-
    hornguard_admit(iso, [iso], call(_), refused(_, escape_attempt, _)).

% Fail closed on meta-predicates: a host allow of a predicate the engine
% declares meta, with no spec from any profile in force, is refused. Once
% the profile carrying the spec is in force the same goal is admitted.
test(host_allow_of_engine_meta_without_spec_refused,
     [true(V = refused(_, benign_miss, meta_spec(aggregate_all/3)))]) :-
    hornguard_admit(swi, [iso], aggregate_all(count, true, _), [allow([aggregate_all/3])], V).

test(host_allow_of_engine_meta_with_spec_in_force_admitted, [true(V == admit)]) :-
    hornguard_admit(swi, [iso, swi_aggregate], aggregate_all(count, true, _), [allow([aggregate_all/3])], V).

test(host_allow_of_engine_meta_spec_still_judges_goal,
     [true(V = refused(_, escape_attempt, pinned(flags_ops) + depth(1)))]) :-
    hornguard_admit(swi, [iso, swi_aggregate], aggregate_all(count, current_prolog_flag(home, _), _), [allow([aggregate_all/3])], V).

test(iso_backend_cannot_see_meta_gap_and_admits, [true(V == admit)]) :-
    % The judge-only backend has no introspection: this is why iso is never
    % a running backend, and why the swi backend asks the engine.
    hornguard_admit(iso, [iso], aggregate_all(count, true, _), [allow([aggregate_all/3])], V).

% Trust specs are applied, not just recorded.
test(trust_spec_goal_arg_judged, [true(V = refused(_, escape_attempt, pinned(process) + depth(1)))]) :-
    hornguard_admit(iso, [iso], with_tenant(t, halt), [trust([with_tenant/2-with_tenant(?, 0)])], V).

test(trust_spec_closure_completed, [true(V = refused(_, escape_attempt, pinned(flags_ops) + depth(1)))]) :-
    hornguard_admit(iso, [iso], each_tenant(current_prolog_flag(home)), [trust([each_tenant/1-each_tenant(1)])], V).

test(trust_none_does_not_judge_args, [true(V == admit)]) :-
    hornguard_admit(iso, [iso], lookup(halt), [trust([lookup/1-none])], V).

% defer_unknown: a rule may call a rule stored later, but deferral never
% widens the engine surface.
test(defer_unknown_reports_predicate_need,
     [true(V == admit_needs([predicate(defined_afterwards/1)]))]) :-
    hornguard_admit_clause(swi, [iso], (needs_later(X) :- defined_afterwards(X)),
                           [defer_unknown(true)], V).

test(defer_unknown_off_refuses, [true(V = refused(_, benign_miss, unknown))]) :-
    hornguard_admit_clause(swi, [iso], (needs_later(X) :- defined_afterwards(X)), V).

test(defer_unknown_keeps_engine_builtins_refused, [true(V = refused(permission_error(_, _, _), benign_miss, unknown))]) :-
    hornguard_admit(swi, [iso], char_conversion(a, b), [defer_unknown(true)], V).

test(defer_unknown_combines_with_profile_needs,
     [true(V == admit_needs([predicate(later/1), profile(prologue)]))]) :-
    hornguard_admit(swi, [iso], (member(X, [a]), later(X)), [defer_unknown(true)], V).

test(goal_is_never_bound, [true(G == f(X, Y))]) :-
    G = f(X, Y),
    hornguard_admit(iso, [iso], (X = 1, Y = 2), _).

:- end_tests(policy).
