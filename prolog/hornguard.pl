:- module(hornguard,
          [ hornguard_admit/4,          % +Backend, +Profiles, +Goal, -Verdict
            hornguard_admit/5,          % +Backend, +Profiles, +Goal, +Options, -Verdict
            hornguard_admit_clause/4,   % +Backend, +Profiles, +Clause, -Verdict
            hornguard_admit_clause/5,   % +Backend, +Profiles, +Clause, +Options, -Verdict
            hornguard_admit_program/4,  % +Backend, +Profiles, +Clauses, -Verdict
            hornguard_admit_program/5,  % +Backend, +Profiles, +Clauses, +Options, -Verdict
            hornguard_stratification/2, % +Clauses, -Result
            hornguard_floundering/2,    % +ClauseOrGoal, -NegatedGoals
            hornguard_rewrite/3,        % +Backend, +Term, -Guarded
            hornguard_call/1,           % :Goal      judged at the moment it runs
            hornguard_call/2,
            hornguard_call/3,
            hornguard_call/4,
            hornguard_call/5,
            hornguard_call/6,
            hornguard_call/7,
            hornguard_call/8,
            hornguard_catch/3,          % :Goal, ?Catcher, :Recovery
            hornguard_set_runtime_context/1, % +Options
            hornguard_run/4,            % +Backend, +Profiles, +Caps, +Goal
            hornguard_load_profiles/1,  % +Dir
            hornguard_load_policy/1,    % +File
            hornguard_policy/1,         % -Policy
            hornguard_ops/1,            % -Ops
            hornguard_admit/2,          % +Goal, -Verdict        (under the loaded policy)
            hornguard_admit_clause/2,   % +Clause, -Verdict
            hornguard_admit_program/2,  % +Clauses, -Verdict
            hornguard_profiles/1        % -Names
          ]).

:- meta_predicate
    hornguard_call(0),
    hornguard_call(1, ?),
    hornguard_call(2, ?, ?),
    hornguard_call(3, ?, ?, ?),
    hornguard_call(4, ?, ?, ?, ?),
    hornguard_call(5, ?, ?, ?, ?, ?),
    hornguard_call(6, ?, ?, ?, ?, ?, ?),
    hornguard_call(7, ?, ?, ?, ?, ?, ?, ?),
    hornguard_catch(0, ?, 0).

/** <module> Hornguard: default-deny firewall for untrusted Prolog

The judge. Pure: it never executes the term it is given. It walks a goal or a
clause, consults the loaded profiles (allow/2, meta_spec/2) and the pinned
class table (pinned/2), and returns a verdict:

  * `admit`
  * `admit_with(Guarded)`        - under dynamic_dispatch(judged): admissible
                                   as Guarded, the term with every unbound
                                   goal or closure rewritten to a call the
                                   judge sees again at the moment it runs.
                                   Run Guarded, never the original.
  * `admit_needs(Needs)`         - admissible once the host satisfies each
                                   need: profile(Name) for a known profile
                                   not in force, predicate(Indicator) for a
                                   sandboxed predicate not yet stored (only
                                   under defer_unknown(true))
  * `refused(Reason, Class, Rule)`
      Reason: an ISO error term the host may show the author, subject to
              its oracle policy
      Class:  benign_miss | capability_probe | escape_attempt | reconnaissance
            | semantics | evasion
      Rule:   pinned(Class) | unbound_goal | qualified | meta_spec(Indicator)
            | unknown | not_callable | head(Why) | directive | unsupported(What)
            | evaluable(Name/Arity)
            | unstratified(Members, Head-Callee) | floundering(NegatedGoal)
            | cyclic_term | term_depth
              A pinned rule nested inside a meta-argument carries `+ depth(N)`.
              head(Why) is one of control, pinned(Class), profile(Name),
              trusted, qualified.

The `semantics` class is not a threat signal. It marks a program the judge
can admit capability-wise but refuses to store because it has no single
intended meaning: recursion through negation or aggregation
(hornguard_stratification/2), and negation used as if it bound a variable
(hornguard_floundering/2). The latter is refused only under
`strict_negation(true)`, the default; a host that passes
`strict_negation(false)` may still call hornguard_floundering/2 itself and
warn.

Structural rules, in the order the walk applies them:

  1. An unbound goal in call position is refused. Always. This closes
     construct-then-call at the sink.
  2. Module-qualified goals are refused; the sandbox has one module.
  3. The control constructs (,)/2 (;)/2 (->)/2 (*->)/2 and (^)/2 are walked
     through without counting depth.
  4. A predicate in a pinned class is refused before any profile is consulted.
  5. A predicate the host declared `trust(Indicator, Spec)` is admitted with
     its declared meta spec applied and its body not walked.
  6. A predicate allowed by a profile in force has each goal argument judged
     one level deeper; closures are completed to full arity with fresh
     variables first. On backends with introspection, an allowed predicate
     that the engine declares meta but no profile gives a spec for is refused
     (fail closed).
  7. A predicate allowed only by a profile not in force is recorded as a need;
     under defer_unknown(true) so is a predicate the engine does not define.
  8. Anything else is refused as unknown, with an existence or permission
     reason depending on what the backend can tell.

Two more rules apply where the walk would otherwise not look. An
arithmetic predicate's expressions are checked for pinned evaluables (the
clock-reading functions), since arithmetic is a second language inside the
first. And a clause head may not name a predicate the host trusts: the
trusted definition is the one whose body is never walked, and a clause in
sandboxed space would stand in for it.

Rule 1 has one sanctioned relaxation. Under `dynamic_dispatch(judged)` an
unbound goal or closure is not refused but rewritten to hornguard_call/N,
which judges the goal under the same policy at the moment it runs and only
then calls it, and catch/3 becomes hornguard_catch/3, which cannot swallow a
runtime refusal. The verdict is then `admit_with(Guarded)`, and the host runs
Guarded. Judgment happens twice, statically where the goal is known and at
the sink where it is not; nothing runs unjudged either way. The runtime
judge is the loaded policy plus whatever hornguard_set_runtime_context/1 has
set (a namespace's stored predicates, typically), or a host's own
`hornguard:runtime_judge_hook/2` when it wants the judging done in a process
the author cannot reach.

Enforcement (hornguard_run/4) is not yet implemented; it belongs to the
backend layer, not the judge.
*/

:- use_module(library(lists)).
:- use_module(library(apply)).
:- use_module(library(error)).
:- use_module(library(ugraphs)).

:- dynamic hg_allow/2,          % Profile, Name/Arity
           hg_meta/2,           % Profile, Spec (meta_predicate notation)
           hg_pinned/2,         % Class, Name/Arity (Arity may be unbound)
           hg_pinned_evaluable/2, % Class, Name/Arity of an arithmetic function
           hg_unpinned/2,       % Class, Name/Arity  (moved aside by a policy unpin)
           hg_engine/2,         % Backend, Name/Arity   (what the engine defines)
           hg_enforcement/2,    % Backend, native | external | none
           hg_policy/1,         % policy(Backend, Profiles, Options, Allow, Trust)
           hg_op/3,             % Priority, Type, Name: operators the reader honours
           hg_loaded_dir/1,
           hg_default_dir/1.

%   hornguard:runtime_judge_hook(+Goal, -Verdict)
%
%   A host that wants hornguard_call/N judged somewhere the author's code
%   cannot reach (its judge worker, say) defines this. Verdict is any
%   verdict hornguard_admit/5 returns under dynamic_dispatch(judged).
%   Dynamic as well as multifile so a host can install it at run time.
:- multifile runtime_judge_hook/2.
:- dynamic runtime_judge_hook/2.

:- prolog_load_context(directory, Dir),
   atomic_list_concat([Dir, '/../profiles'], Rel),
   absolute_file_name(Rel, Abs),
   retractall(hg_default_dir(_)),
   assertz(hg_default_dir(Abs)).


		 /*******************************
		 *           PROFILES           *
		 *******************************/

%!  hornguard_load_profiles(+DirOrDirs) is det.
%
%   Replace the loaded profiles with every `.pl` profile file under the
%   given directory, or under each of a list of directories in order. A
%   host installs its own profiles by naming its directory after the
%   library's: the shipped profiles and the host's load into one table,
%   and the policy check runs over the union.
%
%   The directory holds profiles and backend manifests. Accepted terms:
%   allow(Profile, Name/Arity), meta_spec(Profile, Spec),
%   pinned(Class, Name/Arity), pinned_evaluable(Class, Name/Arity),
%   engine(Backend, Name/Arity), enforcement(Backend, Kind) and directives
%   (ignored). Anything else is a domain_error. An allow that names a pinned
%   indicator is a load error: pinned classes are not reopened by profile.
%
%   Every file is read and checked before any table changes, so a directory
%   that fails to load leaves the profiles that were in force exactly as
%   they were.

hornguard_load_profiles(DirOrDirs) :-
    (   is_list(DirOrDirs) -> Dirs = DirOrDirs ; Dirs = [DirOrDirs] ),
    must_be(list(atom), Dirs),
    foldl(hg_collect_profile_dir, Dirs, [], Facts0),
    reverse(Facts0, Facts),
    hg_check_profile_pins(Facts),
    retractall(hg_allow(_, _)),
    retractall(hg_meta(_, _)),
    retractall(hg_pinned(_, _)),
    retractall(hg_pinned_evaluable(_, _)),
    retractall(hg_unpinned(_, _)),
    retractall(hg_engine(_, _)),
    retractall(hg_enforcement(_, _)),
    retractall(hg_op(_, _, _)),
    retractall(hg_loaded_dir(_)),
    forall(member(Fact, Facts), assertz(Fact)),
    assertz(hg_loaded_dir(Dirs)).

%!  hornguard_ops(-Ops) is det.
%
%   The operators the loaded profiles declare, as op(Priority, Type, Name)
%   terms. A host whose stored rules use an operator (a battery's `::`,
%   say) declares it in its profiles directory; the judge worker's reader
%   honours it, and the canonical form it emits is operator-free, so the
%   engine never needs to know. op/3 itself stays pinned for authors.

hornguard_ops(Ops) :-
    hg_ensure_profiles,
    findall(op(P, T, N), hg_op(P, T, N), Ops).

hg_collect_profile_dir(Dir, Acc0, Acc) :-
    directory_files(Dir, Entries),
    include(hg_profile_file, Entries, Files0),
    msort(Files0, Files),
    foldl(hg_collect_profile_file(Dir), Files, Acc0, Acc).

hg_profile_file(F) :-
    file_name_extension(_, pl, F).

hg_collect_profile_file(Dir, F, Acc0, Acc) :-
    directory_file_path(Dir, F, Path),
    setup_call_cleanup(
        open(Path, read, In),
        hg_collect_profile_terms(In, Path, Acc0, Acc),
        close(In)).

hg_collect_profile_terms(In, Path, Acc0, Acc) :-
    read_term(In, Term, [module(hornguard)]),
    (   Term == end_of_file
    ->  Acc = Acc0
    ;   hg_profile_fact(Term, Path, Acc0, Acc1),
        hg_collect_profile_terms(In, Path, Acc1, Acc)
    ).

%   The fact a profile term becomes, consed onto the accumulator; the list
%   is reversed once before it is asserted so file order is kept.
hg_profile_fact(allow(P, N/A), _, Acc, [hg_allow(P, N/A)|Acc]) :-
    atom(P), atom(N), integer(A), !.
hg_profile_fact(meta_spec(P, Spec), _, Acc, [hg_meta(P, Spec)|Acc]) :-
    atom(P), callable(Spec), !.
hg_profile_fact(pinned(C, N/A), _, Acc, [hg_pinned(C, N/A)|Acc]) :-
    atom(C), atom(N), ( var(A) ; integer(A) ), !.
hg_profile_fact(pinned_evaluable(C, N/A), _, Acc, [hg_pinned_evaluable(C, N/A)|Acc]) :-
    atom(C), atom(N), integer(A), !.
hg_profile_fact(engine(B, N/A), _, Acc, [hg_engine(B, N/A)|Acc]) :-
    atom(B), atom(N), integer(A), !.
hg_profile_fact(enforcement(B, Kind), _, Acc, [hg_enforcement(B, Kind)|Acc]) :-
    atom(B), hg_enforcement_kind(Kind), !.
hg_profile_fact(op(P, T, N), _, Acc, [hg_op(P, T, N)|Acc]) :-
    integer(P), P >= 0, P =< 1200, atom(T), atom(N), !.
hg_profile_fact((:- _), _, Acc, Acc) :- !.
hg_profile_fact(Term, Path, _, _) :-
    throw(error(domain_error(hornguard_profile_term, Term), context(Path, _))).

%   What a backend can do about a running goal.
%
%     native    the engine gives the judge's host time, inference and stack
%               caps, isolation, and an abort the author cannot catch
%     external  the host must supply them from outside the engine (a process
%               wrapper, a runtime), and must say so before running anything
%     none      judge-only; the backend refuses to run
hg_enforcement_kind(native).
hg_enforcement_kind(external).
hg_enforcement_kind(none).

hg_check_profile_pins(Facts) :-
    forall(member(hg_allow(P, N/A), Facts),
           (   member(hg_pinned(C, N/A), Facts)
           ->  throw(error(permission_error(allow, pinned(C), N/A),
                           context(profile(P), 'pinned classes are not reopened by profile')))
           ;   true
           )).

hg_ensure_profiles :-
    (   hg_loaded_dir(_)
    ->  true
    ;   hg_default_dir(Dir),
        hornguard_load_profiles(Dir)
    ).

%!  hornguard_profiles(-Names) is det.
%
%   The profile names the loaded policy knows about.

hornguard_profiles(Names) :-
    hg_ensure_profiles,
    setof(P, I^hg_allow(P, I), Names).

		 /*******************************
		 *            POLICY            *
		 *******************************/

%!  hornguard_load_policy(+File) is det.
%
%   Load a host policy: what the host adds on top of the profiles. The
%   file holds Prolog facts, read with read_term/2 and never consulted:
%
%     * backend(Name)                 default iso
%     * profiles(List)                profiles in force; default [iso]
%     * option(Opt)                   strict_negation(B) | defer_unknown(B)
%     * allow(Name/Arity)             a sandboxed predicate whose clauses
%                                     were body-judged at storage
%     * trust(Name/Arity, Spec)       a host predicate admitted without
%                                     walking its body; Spec is `none` or a
%                                     meta_predicate-style term of the same
%                                     name and arity
%     * unpin(Class)                  reopen a pinned class. Logged as a
%                                     warning at load, every time.
%
%   Load errors are thrown: an allow that names a pinned indicator (unless
%   that class is unpinned in the same file), a trust spec whose name or
%   arity does not match, an unknown profile, an unknown option, or any
%   other term. Loading replaces the previous policy.

hornguard_load_policy(File) :-
    hg_ensure_profiles,
    must_be(atom, File),
    setup_call_cleanup(open(File, read, In),
                       hg_read_policy_terms(In, File, [], Terms0),
                       close(In)),
    reverse(Terms0, Terms),
    hg_install_policy(Terms, File).

hg_read_policy_terms(In, File, Acc, Terms) :-
    read_term(In, T, [module(hornguard)]),
    (   T == end_of_file
    ->  Terms = Acc
    ;   hg_read_policy_terms(In, File, [T|Acc], Terms)
    ).

%   The whole file is validated before anything changes, so a file that
%   fails to load leaves the policy and the pins exactly as they were. The
%   unpins it asks for are known while the allows are checked, since an
%   allow of a class the same file reopens is what the file means.
hg_install_policy(Terms, File) :-
    foldl(hg_policy_term(File), Terms, pol(iso, [iso], [], [], []), pol(B, Ps, Os, Al, Tr)),
    findall(C, member(unpin(C), Terms), Unpins0),
    sort(Unpins0, Unpins),
    forall(member(C, Unpins), hg_check_unpin_class(C, File)),
    hg_check_host_allows(Al, Unpins, File),
    hg_repin_all,
    forall(member(C, Unpins), hg_unpin(C, File)),
    retractall(hg_policy(_)),
    assertz(hg_policy(policy(B, Ps, Os, Al, Tr))).

hg_check_unpin_class(Class, File) :-
    (   atom(Class), ( hg_pinned(Class, _) ; hg_unpinned(Class, _) )
    ->  true
    ;   throw(error(domain_error(hornguard_pinned_class, Class), context(File, _)))
    ).

hg_policy_term(_, unpin(_), P, P) :- !.
hg_policy_term(_, (:- _), P, P) :- !.
hg_policy_term(File, backend(B), pol(_, Ps, Os, Al, Tr), pol(B, Ps, Os, Al, Tr)) :- !,
    hg_policy_check(atom(B), File, backend(B)).
hg_policy_term(File, profiles(Ps), pol(B, _, Os, Al, Tr), pol(B, Ps, Os, Al, Tr)) :- !,
    hg_policy_check(is_list(Ps), File, profiles(Ps)),
    forall(member(P, Ps),
           hg_policy_check(hg_allow(P, _), File, unknown_profile(P))).
hg_policy_term(File, option(O), pol(B, Ps, Os, Al, Tr), pol(B, Ps, [O|Os], Al, Tr)) :- !,
    hg_policy_check(hg_policy_option(O), File, option(O)).
hg_policy_term(File, allow(Ind), pol(B, Ps, Os, Al, Tr), pol(B, Ps, Os, [Ind|Al], Tr)) :- !,
    hg_policy_check(hg_indicator_term(Ind), File, allow(Ind)).
hg_policy_term(File, trust(Ind, Spec), pol(B, Ps, Os, Al, Tr), pol(B, Ps, Os, Al, [Ind-Spec|Tr])) :- !,
    hg_policy_check(hg_indicator_term(Ind), File, trust(Ind, Spec)),
    hg_policy_check(hg_trust_spec_ok(Ind, Spec), File, trust_spec(Ind, Spec)).
hg_policy_term(File, Term, _, _) :-
    throw(error(domain_error(hornguard_policy_term, Term), context(File, _))).

hg_policy_check(Goal, _, _) :- call(Goal), !.
hg_policy_check(_, File, What) :-
    throw(error(domain_error(hornguard_policy, What), context(File, _))).

hg_policy_option(strict_negation(B)) :- hg_bool(B).
hg_policy_option(defer_unknown(B)) :- hg_bool(B).

hg_bool(true).
hg_bool(false).

hg_indicator_term(N/A) :- atom(N), integer(A), A >= 0.

hg_trust_spec_ok(_, none) :- !.
hg_trust_spec_ok(N/A, Spec) :- callable(Spec), functor(Spec, N, A).

hg_check_host_allows(Allows, Unpins, File) :-
    forall(member(Ind, Allows),
           (   ( hg_pinned(C, Ind) ; hg_unpinned(C, Ind) ),
               \+ memberchk(C, Unpins)
           ->  throw(error(permission_error(allow, pinned(C), Ind),
                           context(File, 'pinned classes are reopened with unpin/1, never by allow/1')))
           ;   true
           )).

%   Unpinning moves the class's entries aside so they can be restored when
%   the next policy loads. It is always reported.
hg_unpin(Class, File) :-
    must_be(atom, Class),
    findall(Ind, hg_pinned(Class, Ind), Inds),
    (   Inds == []
    ->  throw(error(domain_error(hornguard_pinned_class, Class), context(File, _)))
    ;   forall(member(Ind, Inds),
               ( retract(hg_pinned(Class, Ind)),
                 assertz(hg_unpinned(Class, Ind)) )),
        length(Inds, N),
        print_message(warning, hornguard(unpinned(Class, N, File)))
    ).

hg_repin_all :-
    forall(retract(hg_unpinned(Class, Ind)), assertz(hg_pinned(Class, Ind))).

:- multifile prolog:message//1.
prolog:message(hornguard(unpinned(Class, N, File))) -->
    [ 'hornguard: policy ~w reopens pinned class ~w (~d indicators). '-[File, Class, N],
      'Every goal in that class is now admissible to authors.' ].

%!  hornguard_policy(-Policy) is det.
%
%   The loaded policy as policy(Backend, Profiles, Options, Allow, Trust),
%   or the default policy(iso, [iso], [], [], []) when none is loaded.

hornguard_policy(P) :-
    (   hg_policy(P0) -> P = P0
    ;   P = policy(iso, [iso], [], [], [])
    ).

%!  hornguard_admit(+Goal, -Verdict) is det.
%!  hornguard_admit_clause(+Clause, -Verdict) is det.
%!  hornguard_admit_program(+Clauses, -Verdict) is det.
%
%   Judge under the loaded policy.

hornguard_admit(Goal, Verdict) :-
    hg_policy_call(hornguard_admit, Goal, Verdict).
hornguard_admit_clause(Clause, Verdict) :-
    hg_policy_call(hornguard_admit_clause, Clause, Verdict).
hornguard_admit_program(Clauses, Verdict) :-
    hg_policy_call(hornguard_admit_program, Clauses, Verdict).

hg_policy_call(Pred, Term, Verdict) :-
    hornguard_policy(policy(B, Ps, Os, Al, Tr)),
    Options = [allow(Al), trust(Tr)|Os],
    call(Pred, B, Ps, Term, Options, Verdict).


		 /*******************************
		 *            JUDGE             *
		 *******************************/

%!  hornguard_admit(+Backend, +Profiles, +Goal, -Verdict) is det.
%!  hornguard_admit(+Backend, +Profiles, +Goal, +Options, -Verdict) is det.
%
%   Judge Goal under the named Profiles. Goal is never executed and never
%   bound. Options:
%
%     * allow(ListOfIndicators)
%       Host predicates whose clauses live in sandboxed space and were
%       body-judged at storage. Admitted like a profile entry, no spec.
%     * trust(ListOf(Indicator-Spec))
%       Host predicates admitted without walking their bodies. Spec is a
%       meta_predicate-style term or the atom `none`.
%     * strict_negation(Bool)
%       Default true: a negated goal that introduces a variable used later
%       is refused under `semantics`. False skips the refusal.
%     * defer_unknown(Bool)
%       Default false. True reports an indicator the engine does not define
%       as predicate(Indicator) in admit_needs instead of refusing it, so a
%       stored rule may call a rule stored later. Engine-defined predicates
%       no profile allows are still refused.

hornguard_admit(Backend, Profiles, Goal, Verdict) :-
    hornguard_admit(Backend, Profiles, Goal, [], Verdict).

hornguard_admit(Backend, Profiles0, Goal0, Options, Verdict) :-
    hg_ensure_profiles,
    hg_dynamic_mode(Options, Mode, Profiles0, Profiles),
    hg_context(Backend, Profiles, Options, Ctx),
    hg_strict_negation(Options, Strict),
    hg_prepared(Mode, goal, Goal0, Ctx, Goal1, Verdict0),
    (   nonvar(Verdict0)
    ->  Verdict = Verdict0
    ;   hg_judged(Goal1, Goal,
                  ( hg_goal(Goal, 0, Ctx, [], Needs0),
                    hg_check_floundering(Strict, Goal),
                    hg_needs_verdict(Needs0, Verdict1) ),
                  Verdict1),
        hg_mode_verdict(Mode, Verdict1, Goal1, Verdict)
    ).

%   hg_prepared(+Mode, +Kind, +Term0, +Ctx, -Term, -Verdict)
%
%   Under judged mode, Term is Term0 with its unbound sinks rewritten; the
%   rewrite shares Term0's variables, so a host's variable names still map.
%   The shapes that would defeat the rewrite (a cyclic term, a term too deep
%   to walk) are refused here, as the judge would refuse them.
hg_prepared(refused, _, Term, _, Term, _) :- !.
hg_prepared(judged, Kind, Term0, Ctx, Term, Verdict) :-
    (   \+ acyclic_term(Term0)
    ->  Term = Term0,
        Verdict = refused(type_error(acyclic_term, cyclic), evasion, cyclic_term)
    ;   catch(hg_guard_kind(Kind, Term0, Ctx, Term),
              error(resource_error(What), _),
              ( Term = Term0,
                Verdict = refused(resource_error(What), evasion, term_depth) ))
    ).

hg_guard_kind(goal, Goal, Ctx, Guarded) :-
    hg_guard_goal(Goal, Ctx, Guarded).
hg_guard_kind(clause, Clause, Ctx, Guarded) :-
    hg_guard_clause(Clause, Ctx, Guarded).
hg_guard_kind(program, Clauses, Ctx, Guarded) :-
    (   is_list(Clauses)
    ->  maplist([C, G]>>hg_guard_clause(C, Ctx, G), Clauses, Guarded)
    ;   Guarded = Clauses
    ).

hg_guard_clause((Head :- Body), Ctx, (Head :- Guarded)) :- !,
    hg_guard_goal(Body, Ctx, Guarded).
hg_guard_clause(Clause, _, Clause).

%   hg_judged(+Term0, -Term, :Judgment, -Verdict)
%
%   Run Judgment over a private copy of Term0 and turn every way it can
%   stop into a verdict. Attributes are stripped from the copy so no
%   coroutine attached to the caller's term can fire inside the judge. A
%   cyclic term is refused before the walk, because the walk would not
%   terminate on it. A walk that exhausts a stack on a pathologically deep
%   term is refused rather than surfaced as an engine error, so the judge
%   never dies where it was asked to decide.
hg_judged(Term0, Term, Judgment, Verdict) :-
    copy_term_nat(Term0, Term),
    (   acyclic_term(Term)
    ->  catch(Judgment, E, hg_exception_verdict(E, Verdict))
    ;   Verdict = refused(type_error(acyclic_term, cyclic), evasion, cyclic_term)
    ).

%   Commit to the translation before touching the output argument, so a
%   caller that passes a partially bound Verdict gets failure rather than
%   the internal exception.
hg_exception_verdict(E, Verdict) :-
    hg_verdict_of_exception(E, V), !,
    Verdict = V.
hg_exception_verdict(E, _) :-
    throw(E).

hg_verdict_of_exception(hg_refused(Reason, Class, Rule), refused(Reason, Class, Rule)).
hg_verdict_of_exception(error(resource_error(What), _),
                        refused(resource_error(What), evasion, term_depth)).

hg_strict_negation(Options, Strict) :-
    (   memberchk(strict_negation(S), Options)
    ->  must_be(boolean, S), Strict = S
    ;   Strict = true
    ).

%!  hornguard_admit_clause(+Backend, +Profiles, +Clause, -Verdict) is det.
%!  hornguard_admit_clause(+Backend, +Profiles, +Clause, +Options, -Verdict) is det.
%
%   Judge a clause for storage. The body is judged exactly as a goal. The
%   head may not be unbound, module-qualified, a control construct, or an
%   indicator that a pinned class or a loaded profile already claims: a
%   stored clause must not shadow anything the judge reasons about.
%   Directives are refused. DCG rules are refused until the translation is
%   judged post-expansion.

hornguard_admit_clause(Backend, Profiles, Clause, Verdict) :-
    hornguard_admit_clause(Backend, Profiles, Clause, [], Verdict).

hornguard_admit_clause(Backend, Profiles0, Clause0, Options, Verdict) :-
    hg_ensure_profiles,
    hg_dynamic_mode(Options, Mode, Profiles0, Profiles),
    hg_context(Backend, Profiles, Options, Ctx),
    hg_strict_negation(Options, Strict),
    hg_prepared(Mode, clause, Clause0, Ctx, Clause1, Verdict0),
    (   nonvar(Verdict0)
    ->  Verdict = Verdict0
    ;   hg_judged(Clause1, Clause,
                  ( hg_clause(Clause, Ctx, Needs0),
                    hg_check_floundering(Strict, Clause),
                    hg_needs_verdict(Needs0, Verdict1) ),
                  Verdict1),
        hg_mode_verdict(Mode, Verdict1, Clause1, Verdict)
    ).

hg_needs_verdict([], admit) :- !.
hg_needs_verdict(Needs0, admit_needs(Needs)) :-
    sort(Needs0, Needs).

hg_context(Backend, Profiles, Options, ctx(Backend, Profiles, Allow, Trust, Defer, Defining)) :-
    must_be(atom, Backend),
    must_be(list(atom), Profiles),
    must_be(list, Options),
    (   memberchk(allow(Allow0), Options) -> must_be(list, Allow0), Allow = Allow0
    ;   Allow = []
    ),
    (   memberchk(trust(Trust0), Options) -> must_be(list, Trust0), Trust = Trust0
    ;   Trust = []
    ),
    (   memberchk(defer_unknown(D), Options) -> must_be(boolean, D), Defer = D
    ;   Defer = false
    ),
    (   memberchk(defining(Df), Options) -> must_be(list(atom), Df), Defining = Df
    ;   Defining = []
    ).

%   dynamic_dispatch(refused), the default, is rule 1 as written. Under
%   judged, the term is rewritten before it is judged and the runtime profile
%   joins the profiles in force so the rewritten calls are admissible.
hg_dynamic_mode(Options, Mode, Profiles0, Profiles) :-
    (   memberchk(dynamic_dispatch(M), Options)
    ->  must_be(oneof([refused, judged]), M), Mode = M
    ;   Mode = refused
    ),
    (   Mode == judged, \+ memberchk(hornguard_runtime, Profiles0)
    ->  Profiles = [hornguard_runtime|Profiles0]
    ;   Profiles = Profiles0
    ).

%   Under judged mode, admission of the guarded term is admission with it.
hg_mode_verdict(judged, admit, Guarded, admit_with(Guarded)) :- !.
hg_mode_verdict(_, Verdict, _, Verdict).

%   hg_goal(+Goal, +Depth, +Ctx, +Needs0, -Needs)
%
%   Succeeds if Goal is admissible, accumulating profiles it needs; throws
%   hg_refused/3 at the first refusal. Depth counts meta-argument nesting.

hg_goal(Var, _, _, _, _) :-
    var(Var), !,
    throw(hg_refused(instantiation_error, escape_attempt, unbound_goal)).
hg_goal(_:_, _, _, _, _) :- !,
    throw(hg_refused(permission_error(execute, goal, (:)/2), escape_attempt, qualified)).
hg_goal((A, B), D, Ctx, N0, N) :- !,
    hg_goal(A, D, Ctx, N0, N1),
    hg_goal(B, D, Ctx, N1, N).
hg_goal((A ; B), D, Ctx, N0, N) :- !,
    hg_goal(A, D, Ctx, N0, N1),
    hg_goal(B, D, Ctx, N1, N).
hg_goal((A -> B), D, Ctx, N0, N) :- !,
    hg_goal(A, D, Ctx, N0, N1),
    hg_goal(B, D, Ctx, N1, N).
hg_goal((A *-> B), D, Ctx, N0, N) :- !,
    hg_goal(A, D, Ctx, N0, N1),
    hg_goal(B, D, Ctx, N1, N).
hg_goal(_ ^ G, D, Ctx, N0, N) :- !,
    hg_goal(G, D, Ctx, N0, N).
hg_goal(true, _, _, N, N) :- !.
hg_goal(fail, _, _, N, N) :- !.
hg_goal(false, _, _, N, N) :- !.
hg_goal(!, _, _, N, N) :- !.
hg_goal(G, D, Ctx, N0, N) :-
    callable(G), !,
    functor(G, Name, Arity),
    hg_indicator(G, Name/Arity, D, Ctx, N0, N),
    hg_check_evaluables(G, Name/Arity, D).
hg_goal(G, _, _, _, _) :-
    throw(hg_refused(type_error(callable, G), benign_miss, not_callable)).

%   Arithmetic is a second language the walk would otherwise not look into.
%   Its functions are pure except the ones that read the clock, which hand
%   an author the timing channel the `timing` pin exists to close, so the
%   expressions of an arithmetic predicate are checked for pinned
%   evaluables (profiles/pinned.pl, `pinned_evaluable/2`). Refused with the
%   same class and depth a pinned goal would carry at that position.
hg_check_evaluables(G, Ind, D) :-
    (   hg_arith_indicator(Ind)
    ->  G =.. [_|Args],
        forall(member(A, Args), hg_check_expr(A, D))
    ;   true
    ).

hg_arith_indicator((is)/2).
hg_arith_indicator((=:=)/2).
hg_arith_indicator((=\=)/2).
hg_arith_indicator((<)/2).
hg_arith_indicator((>)/2).
hg_arith_indicator((=<)/2).
hg_arith_indicator((>=)/2).

hg_check_expr(V, _) :-
    var(V), !.
hg_check_expr(E, D) :-
    atom(E), !,
    hg_check_evaluable(E/0, D).
hg_check_expr(E, D) :-
    compound(E), !,
    functor(E, F, A),
    hg_check_evaluable(F/A, D),
    E =.. [_|Args],
    forall(member(Arg, Args), hg_check_expr(Arg, D)).
hg_check_expr(_, _).

hg_check_evaluable(Ind, D) :-
    (   hg_pinned_evaluable(Class, Ind)
    ->  hg_pinned_report_class(Class, D, Report),
        hg_depth_rule(evaluable(Ind), D, Rule),
        throw(hg_refused(permission_error(evaluate, evaluable, Ind), Report, Rule))
    ;   true
    ).

hg_indicator(G, Ind, D, Ctx, N0, N) :-
    (   hg_pinned(PinClass, Ind)
    ->  hg_pinned_report_class(PinClass, D, Class),
        hg_depth_rule(pinned(PinClass), D, Rule),
        throw(hg_refused(permission_error(execute, goal, Ind), Class, Rule))
    ;   hg_trusted(Ind, Ctx, Spec)
    ->  hg_apply_spec(Spec, G, D, Ctx, N0, N)
    ;   hg_in_force(Ind, Ctx)
    ->  (   hg_spec_in_force(Ind, Ctx, Spec)
        ->  hg_apply_spec(Spec, G, D, Ctx, N0, N)
        ;   hg_engine_meta_gap(Ctx, G)
        ->  throw(hg_refused(permission_error(execute, goal, Ind), benign_miss, meta_spec(Ind)))
        ;   N = N0
        )
    ;   hg_available(Ind, Profile)
    ->  (   hg_spec_in_profile(Ind, Profile, Spec)
        ->  hg_apply_spec(Spec, G, D, Ctx, [profile(Profile)|N0], N)
        ;   N = [profile(Profile)|N0]
        )
    ;   hg_deferrable(Ctx, G, Ind)
    ->  N = [predicate(Ind)|N0]
    ;   hg_unknown_reason(Ctx, G, Ind, Reason),
        throw(hg_refused(Reason, benign_miss, unknown))
    ).

%   Under defer_unknown(true) an indicator the engine does not define is a
%   sandboxed predicate the host has not stored yet. It is reported as a
%   need rather than refused, so a rule may be stored before the rules it
%   calls. An indicator the engine does define but no profile allows stays
%   a refusal: deferral never widens the engine surface.
%
%   What the engine defines is hg_engine_defines/3's answer and nothing
%   else's, so deferral and the refusal reason can never disagree about it.
%   Keep it that way: a second predicate answering the same question for
%   swi alone once lived here, and every manifest backend deferred what it
%   should have refused.
hg_deferrable(Ctx, G, Ind) :-
    Ctx = ctx(_, _, _, _, true, _),
    \+ hg_engine_defines(Ctx, G, Ind).

%   Reflection is reconnaissance wherever it appears. Any other pinned
%   class is a probe at the top level and an escape attempt once it is
%   hidden inside a meta-argument: the author expected the outer goal to
%   pass.
hg_pinned_report_class(reflection, _, reconnaissance) :- !.
hg_pinned_report_class(_, 0, capability_probe) :- !.
hg_pinned_report_class(_, _, escape_attempt).

hg_depth_rule(Rule, 0, Rule) :- !.
hg_depth_rule(Rule, D, Rule + depth(D)).

hg_trusted(Ind, ctx(_, _, _, Trust, _, _), Spec) :-
    memberchk(Ind-Spec, Trust).

hg_in_force(Ind, ctx(_, Profiles, Allow, _, _, _)) :-
    (   member(P, Profiles), hg_allow(P, Ind)
    ->  true
    ;   memberchk(Ind, Allow)
    ).

hg_spec_in_force(Name/Arity, ctx(_, Profiles, _, _, _, _), Spec) :-
    functor(Spec, Name, Arity),
    member(P, Profiles),
    hg_meta(P, Spec), !.

hg_available(Ind, Profile) :-
    hg_allow(Profile, Ind), !.

hg_spec_in_profile(Name/Arity, Profile, Spec) :-
    functor(Spec, Name, Arity),
    hg_meta(Profile, Spec), !.

%   Apply a meta_predicate-style spec to the arguments of G. `0` and `^`
%   arguments are goals; an integer K > 0 is a closure completed with K
%   fresh arguments; anything else is data.
hg_apply_spec(none, _, _, _, N, N) :- !.
hg_apply_spec(Spec, G, D, Ctx, N0, N) :-
    D1 is D + 1,
    Spec =.. [_|Modes],
    G =.. [_|Args],
    hg_apply_modes(Modes, Args, D1, Ctx, N0, N).

hg_apply_modes([], [], _, _, N, N).
hg_apply_modes([M|Ms], [A|As], D, Ctx, N0, N) :-
    hg_apply_mode(M, A, D, Ctx, N0, N1),
    hg_apply_modes(Ms, As, D, Ctx, N1, N).

hg_apply_mode(0, A, D, Ctx, N0, N) :- !,
    hg_goal(A, D, Ctx, N0, N).
hg_apply_mode(^, A, D, Ctx, N0, N) :- !,
    hg_strip_existential(A, G),
    hg_goal(G, D, Ctx, N0, N).
hg_apply_mode(K, A, D, Ctx, N0, N) :-
    integer(K), K > 0, !,
    hg_complete_closure(A, K, G),
    hg_goal(G, D, Ctx, N0, N).
hg_apply_mode(_, _, _, _, N, N).

hg_strip_existential(V, V) :- var(V), !.
hg_strip_existential(_ ^ G0, G) :- !, hg_strip_existential(G0, G).
hg_strip_existential(G, G).

%   An unbound or qualified closure is left alone so hg_goal refuses it
%   under the right rule; anything else gets K fresh arguments appended.
hg_complete_closure(V, _, V) :- var(V), !.
hg_complete_closure(M:C, _, M:C) :- !.
hg_complete_closure(C, K, G) :-
    callable(C), !,
    C =.. L0,
    length(Fresh, K),
    append(L0, Fresh, L),
    G =.. L.
hg_complete_closure(C, _, C).


		 /*******************************
		 *           CLAUSES            *
		 *******************************/

hg_clause(Var, _, _) :-
    var(Var), !,
    throw(hg_refused(instantiation_error, escape_attempt, unbound_clause)).
hg_clause((:- _), _, _) :- !,
    throw(hg_refused(permission_error(execute, directive, (:-)/1), capability_probe, directive)).
hg_clause((?- _), _, _) :- !,
    throw(hg_refused(permission_error(execute, directive, (?-)/1), capability_probe, directive)).
hg_clause((_ --> _), _, _) :- !,
    throw(hg_refused(permission_error(modify, static_procedure, (-->)/2), benign_miss, unsupported(dcg))).
hg_clause((Head :- Body), Ctx0, Needs) :- !,
    hg_head(Head, Ctx0),
    hg_allow_head_in_body(Head, Ctx0, Ctx),
    hg_goal(Body, 0, Ctx, [], Needs).
hg_clause(Head, Ctx, []) :-
    hg_head(Head, Ctx).

%   A clause may call its own head: recursion is the normal shape of a rule.
%   Any other sandboxed predicate has to arrive through the allow/1 option,
%   because only the host knows what else is stored.
hg_allow_head_in_body(Head, ctx(B, P, Allow, Trust, D, Df), ctx(B, P, [Ind|Allow], Trust, D, Df)) :-
    functor(Head, Name, Arity),
    Ind = Name/Arity.

%   A head may not name anything the judge reasons about: a control
%   construct, a pinned or profile predicate, or a predicate the host
%   trusts. The trusted case is the one that is easy to miss: the host's
%   definition is the one whose body is never walked, so a clause in
%   sandboxed space with that head would stand in for it.
hg_head(Var, _) :-
    var(Var), !,
    throw(hg_refused(instantiation_error, escape_attempt, unbound_head)).
hg_head(_:_, _) :- !,
    throw(hg_refused(permission_error(modify, static_procedure, (:)/2), escape_attempt, head(qualified))).
hg_head(Head, Ctx) :-
    callable(Head), !,
    functor(Head, Name, Arity),
    Ind = Name/Arity,
    (   hg_control_indicator(Ind)
    ->  throw(hg_refused(permission_error(modify, static_procedure, Ind), escape_attempt, head(control)))
    ;   hg_pinned(Class, Ind)
    ->  throw(hg_refused(permission_error(modify, static_procedure, Ind), escape_attempt, head(pinned(Class))))
    ;   hg_trusted(Ind, Ctx, _)
    ->  throw(hg_refused(permission_error(modify, static_procedure, Ind), escape_attempt, head(trusted)))
    ;   hg_allow(Profile, Ind), \+ hg_defining(Profile, Ctx)
    ->  throw(hg_refused(permission_error(modify, static_procedure, Ind), escape_attempt, head(profile(Profile))))
    ;   true
    ).
hg_head(Head, _) :-
    throw(hg_refused(type_error(callable, Head), benign_miss, not_callable)).

%   A host judging the program that *is* a profile (a battery's clauses,
%   installed once as platform code) names that profile in defining/1; its
%   heads are then the definitions the profile promises, not shadows of them.
hg_defining(Profile, ctx(_, _, _, _, _, Defining)) :-
    memberchk(Profile, Defining).

hg_control_indicator((',')/2).
hg_control_indicator((;)/2).
hg_control_indicator((->)/2).
hg_control_indicator((*->)/2).
hg_control_indicator((^)/2).
hg_control_indicator((:)/2).
hg_control_indicator(true/0).
hg_control_indicator(fail/0).
hg_control_indicator(false/0).
hg_control_indicator((!)/0).


		 /*******************************
		 *           PROGRAMS           *
		 *******************************/

%!  hornguard_admit_program(+Backend, +Profiles, +Clauses, -Verdict) is det.
%!  hornguard_admit_program(+Backend, +Profiles, +Clauses, +Options, -Verdict) is det.
%
%   Judge a clause set for storage as one program. Every clause is judged
%   as by hornguard_admit_clause/5 with the program's own heads admitted in
%   bodies, so rules may call each other. Then the program must be
%   stratified: no recursion through negation or aggregation. A capability
%   refusal wins over a semantics refusal; the first refusal in clause order
%   is reported.

hornguard_admit_program(Backend, Profiles, Clauses, Verdict) :-
    hornguard_admit_program(Backend, Profiles, Clauses, [], Verdict).

hornguard_admit_program(Backend, Profiles0, Clauses0, Options, Verdict) :-
    hg_ensure_profiles,
    must_be(list, Clauses0),
    hg_dynamic_mode(Options, Mode, Profiles0, Profiles),
    hg_context(Backend, Profiles, Options, Ctx0),
    hg_strict_negation(Options, Strict),
    hg_prepared(Mode, program, Clauses0, Ctx0, Clauses1, Verdict0),
    (   nonvar(Verdict0)
    ->  Verdict = Verdict0
    ;   hg_judged(Clauses1, Clauses,
                  ( hg_program_heads(Clauses, Heads),
                    hg_allow_all(Heads, Ctx0, Ctx),
                    foldl(hg_program_clause(Ctx), Clauses, [], Needs0),
                    forall(member(C, Clauses), hg_check_floundering(Strict, C)),
                    hg_check_stratified(Clauses),
                    hg_needs_verdict(Needs0, Verdict1) ),
                  Verdict1),
        hg_mode_verdict(Mode, Verdict1, Clauses1, Verdict)
    ).

hg_program_clause(Ctx, Clause, N0, N) :-
    hg_clause(Clause, Ctx, Needs),
    append(Needs, N0, N).

hg_program_heads(Clauses, Heads) :-
    findall(Ind, ( member(C, Clauses), hg_clause_head_indicator(C, Ind) ), Heads0),
    sort(Heads0, Heads).

hg_clause_head_indicator(C, _) :- var(C), !, fail.
hg_clause_head_indicator((:- _), _) :- !, fail.
hg_clause_head_indicator((?- _), _) :- !, fail.
hg_clause_head_indicator((_ --> _), _) :- !, fail.
hg_clause_head_indicator((H :- _), Ind) :- !, hg_clause_head_indicator(H, Ind).
hg_clause_head_indicator(_:_, _) :- !, fail.
hg_clause_head_indicator(H, Name/Arity) :-
    callable(H),
    functor(H, Name, Arity).

hg_allow_all(Inds, ctx(B, P, Allow0, Trust, D, Df), ctx(B, P, Allow, Trust, D, Df)) :-
    append(Inds, Allow0, Allow).

hg_check_stratified(Clauses) :-
    hornguard_stratification(Clauses, Result),
    (   Result = unstratified(Members, Edge)
    ->  throw(hg_refused(domain_error(stratified_program, Members), semantics,
                         unstratified(Members, Edge)))
    ;   true
    ).

%!  hornguard_stratification(+Clauses, -Result) is det.
%
%   Result is `stratified(Strata)`, Strata a list of lists of indicators
%   from the lowest stratum up, or `unstratified(Members, Head-Callee)`:
%   the strongly connected predicates that recurse through a negative
%   dependency, and the negative edge that closes the cycle.
%
%   Dependencies are collected from rule bodies. Control constructs are
%   transparent. `\+`, `not/1`, `forall/2`, and the all-solutions and
%   aggregation predicates (`findall`, `bagof`, `setof`, `aggregate_all`)
%   make their goal arguments negative dependencies, as Datalog treats
%   aggregation, because their result depends on the callee being complete.
%   Other meta-predicates pass the current polarity to their goal and
%   closure arguments. Only predicates defined in Clauses take part;
%   everything else is a base relation. Directives and DCG rules are
%   ignored here (hornguard_admit_program/5 refuses them first).

hornguard_stratification(Clauses0, Result) :-
    hg_ensure_profiles,
    must_be(list, Clauses0),
    copy_term(Clauses0, Clauses),
    hg_program_heads(Clauses, Defined),
    findall(E, ( member(C, Clauses), hg_clause_edge(C, Defined, E) ), Edges0),
    sort(Edges0, Edges),
    % Reachability comes from one transitive closure over the dependency
    % graph, polynomial in its size. Enumerating paths with a visited list,
    % which this once did, is exponential on a dense graph: eleven mutually
    % referencing predicates took seconds and fourteen did not finish, which
    % made a small stored program a way to stall the judge.
    findall(H-C, member(edge(H, C, _), Edges), Pairs0),
    sort(Pairs0, Pairs),
    vertices_edges_to_ugraph(Defined, Pairs, Graph),
    transitive_closure(Graph, Closure),
    (   member(edge(H, C, neg), Edges),
        hg_closure_reaches(Closure, C, H)
    ->  findall(P, ( member(P, Defined),
                     ( P == H
                     ; hg_closure_reaches(Closure, H, P), hg_closure_reaches(Closure, P, H)
                     ) ), Ms0),
        sort(Ms0, Members),
        Result = unstratified(Members, H-C)
    ;   hg_strata(Defined, Edges, Strata),
        Result = stratified(Strata)
    ).

%   From reaches To by at least one edge.
hg_closure_reaches(Closure, From, To) :-
    memberchk(From-Successors, Closure),
    memberchk(To, Successors).

hg_clause_edge((H :- B), Defined, edge(HInd, CInd, Sign)) :-
    hg_clause_head_indicator(H, HInd),
    hg_body_dep(B, pos, Defined, CInd, Sign).

%   hg_body_dep(+Body, +Polarity, +Defined, -Callee, -Sign) is nondet.
hg_body_dep(V, _, _, _, _) :- var(V), !, fail.
hg_body_dep((A, B), S, D, C, Sg) :- !, ( hg_body_dep(A, S, D, C, Sg) ; hg_body_dep(B, S, D, C, Sg) ).
hg_body_dep((A ; B), S, D, C, Sg) :- !, ( hg_body_dep(A, S, D, C, Sg) ; hg_body_dep(B, S, D, C, Sg) ).
hg_body_dep((A -> B), S, D, C, Sg) :- !, ( hg_body_dep(A, S, D, C, Sg) ; hg_body_dep(B, S, D, C, Sg) ).
hg_body_dep((A *-> B), S, D, C, Sg) :- !, ( hg_body_dep(A, S, D, C, Sg) ; hg_body_dep(B, S, D, C, Sg) ).
hg_body_dep(_ ^ G, S, D, C, Sg) :- !, hg_body_dep(G, S, D, C, Sg).
hg_body_dep(_:_, _, _, _, _) :- !, fail.
hg_body_dep(G, _, D, C, Sg) :-
    hg_negative_context(G, Inner), !,
    hg_body_dep(Inner, neg, D, C, Sg).
hg_body_dep(G, S, D, C, Sg) :-
    callable(G),
    functor(G, Name, Arity),
    hg_any_meta_spec(Name/Arity, Spec), !,
    (   memberchk(Name/Arity, D), C = Name/Arity, Sg = S
    ;   Spec =.. [_|Modes], G =.. [_|Args],
        nth1(I, Modes, Mode), nth1(I, Args, Arg),
        hg_meta_arg_goal(Mode, Arg, Inner),
        hg_body_dep(Inner, S, D, C, Sg)
    ).
hg_body_dep(G, S, D, Name/Arity, S) :-
    callable(G),
    functor(G, Name, Arity),
    memberchk(Name/Arity, D).

%   Goal arguments whose result depends on the callee being complete.
hg_negative_context(\+ G, G).
hg_negative_context(not(G), G).
hg_negative_context(forall(C, A), (C, A)).
hg_negative_context(findall(_, G, _), G).
hg_negative_context(findall(_, G, _, _), G).
hg_negative_context(bagof(_, G0, _), G) :- hg_strip_existential(G0, G).
hg_negative_context(setof(_, G0, _), G) :- hg_strip_existential(G0, G).
hg_negative_context(aggregate_all(_, G, _), G).
hg_negative_context(aggregate_all(_, _, G, _), G).

hg_any_meta_spec(Name/Arity, Spec) :-
    functor(Spec, Name, Arity),
    hg_meta(_, Spec), !.

hg_meta_arg_goal(0, A, A).
hg_meta_arg_goal(^, A, G) :- hg_strip_existential(A, G).
hg_meta_arg_goal(K, A, G) :- integer(K), K > 0, hg_complete_closure(A, K, G).

		 /*******************************
		 *         FLOUNDERING          *
		 *******************************/

%!  hornguard_floundering(+ClauseOrGoal, -NegatedGoals) is det.
%
%   NegatedGoals are the `\+ G` and `not(G)` goals in the clause body (or
%   in the goal, read as a body with no head) that introduce a variable and
%   then rely on it: the variable does not occur in the head or in any
%   earlier positive goal, and does occur somewhere after the negation.
%   Negation never binds, so such a variable is unbound where it is used.
%
%   A variable that occurs only inside the negated goal is existential and
%   fine (`\+ parent(_, X)`). Aggregation goals (`findall/3` and friends)
%   bind only their result argument; their template and goal variables are
%   local and do not count as bound afterwards. Disjunction is read
%   permissively: an occurrence in any earlier branch counts as bound.

hornguard_floundering(Term0, Goals) :-
    copy_term(Term0, Term),
    hg_floundering(Term, Goals).

hg_floundering((Head :- Body), Goals) :- !,
    term_variables(Head, HeadVars),
    hg_floundering_body(Body, HeadVars, Goals).
hg_floundering(Goal, Goals) :-
    hg_floundering_body(Goal, [], Goals).

hg_floundering_body(Body, HeadVars, Goals) :-
    hg_flatten_body(Body, Entries, []),
    hg_flounder_scan(Entries, HeadVars, Goals).

%   Flatten a body into pos(Goal) and neg(Goal) entries in textual order.
hg_flatten_body(V, [pos(V)|T], T) :- var(V), !.
hg_flatten_body((A, B), E0, E) :- !, hg_flatten_body(A, E0, E1), hg_flatten_body(B, E1, E).
hg_flatten_body((A ; B), E0, E) :- !, hg_flatten_body(A, E0, E1), hg_flatten_body(B, E1, E).
hg_flatten_body((A -> B), E0, E) :- !, hg_flatten_body(A, E0, E1), hg_flatten_body(B, E1, E).
hg_flatten_body((A *-> B), E0, E) :- !, hg_flatten_body(A, E0, E1), hg_flatten_body(B, E1, E).
hg_flatten_body(_ ^ G, E0, E) :- !, hg_flatten_body(G, E0, E).
hg_flatten_body(\+ G, [neg(\+ G)|T], T) :- !.
hg_flatten_body(not(G), [neg(not(G))|T], T) :- !.
hg_flatten_body(G, [pos(G)|T], T).

hg_flounder_scan(Entries, HeadVars, Goals) :-
    hg_flounder_scan(Entries, HeadVars, [], Goals0),
    reverse(Goals0, Goals).

hg_flounder_scan([], _, Acc, Acc).
hg_flounder_scan([pos(G)|Rest], Bound0, Acc, Goals) :-
    hg_binding_vars(G, Vs),
    append(Vs, Bound0, Bound),
    hg_flounder_scan(Rest, Bound, Acc, Goals).
hg_flounder_scan([neg(G)|Rest], Bound, Acc, Goals) :-
    term_variables(G, Vs),
    hg_later_uses(Rest, Later),
    (   member(V, Vs),
        \+ hg_var_memberchk(V, Bound),
        hg_var_memberchk(V, Later)
    ->  Acc1 = [G|Acc]
    ;   Acc1 = Acc
    ),
    hg_flounder_scan(Rest, Bound, Acc1, Goals).

%   A later occurrence counts as a use only where the variable is expected
%   bound: a plain positive goal. Inside a later negation, or inside the
%   template and goal of an aggregation, the same variable name is a fresh
%   local scope and an unbound value there is the intended meaning.
hg_later_uses(Entries, Uses) :-
    foldl(hg_entry_uses, Entries, [], Uses).

hg_entry_uses(neg(_), Acc, Acc).
hg_entry_uses(pos(G), Acc, Uses) :-
    hg_binding_vars(G, Vs),
    append(Vs, Acc, Uses).

%   Which variables a positive goal may leave bound. Aggregation binds its
%   result only; everything else is assumed to bind all its variables.
hg_binding_vars(findall(_, _, L), Vs) :- !, term_variables(L, Vs).
hg_binding_vars(findall(_, _, L, T), Vs) :- !, term_variables(L-T, Vs).
hg_binding_vars(bagof(_, _, L), Vs) :- !, term_variables(L, Vs).
hg_binding_vars(setof(_, _, L), Vs) :- !, term_variables(L, Vs).
hg_binding_vars(aggregate_all(_, _, R), Vs) :- !, term_variables(R, Vs).
hg_binding_vars(aggregate_all(_, _, _, R), Vs) :- !, term_variables(R, Vs).
hg_binding_vars(forall(_, _), []) :- !.
hg_binding_vars(G, Vs) :- term_variables(G, Vs).

hg_var_memberchk(V, [X|Xs]) :-
    (   V == X -> true ; hg_var_memberchk(V, Xs) ).

hg_check_floundering(false, _) :- !.
hg_check_floundering(true, Term) :-
    hg_floundering(Term, Goals),
    (   Goals = [G|_]
    ->  throw(hg_refused(domain_error(safe_negation, G), semantics, floundering(G)))
    ;   true
    ).

%   stratum(P) = max over dependencies of stratum(Q) for a positive edge and
%   stratum(Q) + 1 for a negative one. Iterated to a fixpoint; on a
%   stratified program it converges within |Defined| rounds.
hg_strata(Defined, Edges, Strata) :-
    findall(P-0, member(P, Defined), S0),
    length(Defined, Fuel),
    hg_strata_fix(Edges, S0, Fuel, S),
    (   S == [] -> Strata = []
    ;   findall(L, member(_-L, S), Ls), max_list(Ls, Max),
        findall(Layer, ( between(0, Max, I),
                         findall(P, member(P-I, S), Layer0), msort(Layer0, Layer) ),
                Strata)
    ).

hg_strata_fix(Edges, S0, Fuel, S) :-
    foldl(hg_strata_edge, Edges, S0-false, S1-Changed),
    (   Changed == true, Fuel > 0
    ->  Fuel1 is Fuel - 1,
        hg_strata_fix(Edges, S1, Fuel1, S)
    ;   S = S1
    ).

hg_strata_edge(edge(H, C, Sign), S0-Ch0, S-Ch) :-
    memberchk(C-SC, S0),
    ( Sign == neg -> Need is SC + 1 ; Need = SC ),
    memberchk(H-SH, S0),
    (   SH < Need
    ->  selectchk(H-SH, S0, S1), S = [H-Need|S1], Ch = true
    ;   S = S0, Ch = Ch0
    ).


		 /*******************************
		 *          BACKENDS            *
		 *******************************/

%   What a backend can tell the judge. The `iso` backend knows nothing
%   about the engine, so an allowed predicate without a spec is trusted to
%   be first-order and an unknown predicate is an existence error. The
%   `swi` backend asks the engine.

%   An allowed predicate the engine declares meta, with no spec from any
%   profile in force, is refused rather than admitted with its goal arguments
%   unjudged. Only a backend that can be asked supports this; a manifest
%   records what exists, not what is meta, so on a manifest-driven backend
%   the profiles' specs are the whole story and must be complete.
hg_engine_meta_gap(ctx(swi, _, _, _, _, _), G) :-
    catch(predicate_property(G, meta_predicate(Spec)), _, fail),
    Spec =.. [_|Modes],
    member(Mode, Modes),
    hg_goal_mode(Mode), !.

hg_goal_mode(0).
hg_goal_mode(K) :- integer(K), K > 0.
hg_goal_mode(^).
hg_goal_mode(//).

hg_unknown_reason(Ctx, G, Ind, Reason) :-
    hg_engine_defines(Ctx, G, Ind), !,
    Reason = permission_error(execute, goal, Ind).
hg_unknown_reason(_, _, Ind, existence_error(procedure, Ind)).

%   Does the backend's engine define this? Asked directly on swi, read from
%   the backend's manifest otherwise. A backend with no manifest knows
%   nothing, so everything unrecognised is an existence error and
%   defer_unknown defers it.
hg_engine_defines(ctx(swi, _, _, _, _, _), G, _) :- !,
    catch(predicate_property(G, defined), _, fail).
hg_engine_defines(ctx(Backend, _, _, _, _, _), _, Ind) :-
    hg_engine(Backend, Ind).


		 /*******************************
		 *    DYNAMIC DISPATCH, JUDGED  *
		 *******************************/

%!  hornguard_rewrite(+Backend, +Term, -Guarded) is det.
%
%   Term with every unbound goal or closure in a sink position rewritten to
%   hornguard_call/N, and every catch/3 to hornguard_catch/3. Bound goals
%   are left alone: the judge sees them statically. Uses the loaded profiles'
%   meta specs and the loaded policy's trust specs to know which argument
%   positions are sinks. hornguard_admit/5 under dynamic_dispatch(judged)
%   does this itself and returns the result in admit_with/1; this is the
%   same rewrite for a host that wants it separately.

hornguard_rewrite(Backend, Term, Guarded) :-
    hg_ensure_profiles,
    hornguard_policy(policy(_, _, _, Al, Tr)),
    hg_context(Backend, [], [allow(Al), trust(Tr)], Ctx),
    hg_guard_goal(Term, Ctx, Guarded).

%   The rewrite walks the same positions the judge does, using the same
%   specs, and never binds a variable: the result shares the input's.
hg_guard_goal(V, _, hornguard_call(V)) :-
    var(V), !.
hg_guard_goal(M:G, _, M:G) :- !.
hg_guard_goal((A, B), Ctx, (GA, GB)) :- !,
    hg_guard_goal(A, Ctx, GA), hg_guard_goal(B, Ctx, GB).
hg_guard_goal((A ; B), Ctx, (GA ; GB)) :- !,
    hg_guard_goal(A, Ctx, GA), hg_guard_goal(B, Ctx, GB).
hg_guard_goal((A -> B), Ctx, (GA -> GB)) :- !,
    hg_guard_goal(A, Ctx, GA), hg_guard_goal(B, Ctx, GB).
hg_guard_goal((A *-> B), Ctx, (GA *-> GB)) :- !,
    hg_guard_goal(A, Ctx, GA), hg_guard_goal(B, Ctx, GB).
hg_guard_goal(V ^ G, Ctx, V ^ GG) :- !,
    hg_guard_goal(G, Ctx, GG).
hg_guard_goal(catch(G, E, R), Ctx, hornguard_catch(GG, E, GR)) :- !,
    hg_guard_goal(G, Ctx, GG),
    hg_guard_goal(R, Ctx, GR).
hg_guard_goal(G, _, Guarded) :-
    compound(G), G =.. [call, F|Args],
    hg_unbound_closure(F), !,
    Guarded =.. [hornguard_call, F|Args].
hg_guard_goal(G, Ctx, Guarded) :-
    callable(G),
    functor(G, Name, Arity),
    hg_guard_spec(Name/Arity, Ctx, Spec), !,
    Spec =.. [_|Modes],
    G =.. [Name|Args],
    maplist(hg_guard_arg(Ctx), Modes, Args, GArgs),
    Guarded =.. [Name|GArgs].
hg_guard_goal(G, _, G).

%   A trust spec from the policy, else any loaded profile's spec.
hg_guard_spec(Ind, ctx(_, _, _, Trust, _, _), Spec) :-
    (   memberchk(Ind-Spec0, Trust), Spec0 \== none
    ->  Spec = Spec0
    ;   hg_any_meta_spec(Ind, Spec)
    ).

hg_guard_arg(Ctx, 0, A, GA) :- !,
    hg_guard_goal(A, Ctx, GA).
hg_guard_arg(Ctx, ^, A, GA) :- !,
    hg_guard_goal(A, Ctx, GA).
hg_guard_arg(_, K, A, GA) :-
    integer(K), K > 0, !,
    hg_guard_closure(A, GA).
hg_guard_arg(_, _, A, A).

%   An unbound closure is completed and judged when it is called; so is
%   `call` itself as a closure (maplist(call, Goals)), which is the same
%   thing spelled differently. A bound closure the judge already completed
%   and judged statically is left as it is.
hg_guard_closure(C, hornguard_call(C)) :-
    var(C), !.
hg_guard_closure(call, hornguard_call) :- !.
hg_guard_closure(C, G) :-
    compound(C), C =.. [call|Args], !,
    G =.. [hornguard_call|Args].
hg_guard_closure(C, C).

hg_unbound_closure(F) :- var(F), !.
hg_unbound_closure(call) :- !.
hg_unbound_closure(F) :- compound(F), functor(F, call, _).

%!  hornguard_call(:Goal) is nondet.
%!  hornguard_call(:Closure, ?A1, ...) is nondet.
%
%   Judge Goal under the loaded policy, plus what the host set with
%   hornguard_set_runtime_context/1, at the moment it is called; then call
%   it. In judged mode, so a goal that itself carries an unbound sink is
%   rewritten and judged again when that sink runs. A refusal is thrown as
%
%       error(Reason, hornguard(Class, runtime(Rule)))
%
%   which hornguard_catch/3 will not swallow. A host that wants the judging
%   done outside the engine defines hornguard:runtime_judge_hook/2.

hornguard_call(Goal) :-
    hg_strip_module(Goal, M, G),
    hg_runtime_judge(G, Verdict),
    hg_runtime_proceed(Verdict, M, G).

hornguard_call(G, A) :- hg_extend_closure(G, [A], G1), hornguard_call(G1).
hornguard_call(G, A, B) :- hg_extend_closure(G, [A, B], G1), hornguard_call(G1).
hornguard_call(G, A, B, C) :- hg_extend_closure(G, [A, B, C], G1), hornguard_call(G1).
hornguard_call(G, A, B, C, D) :- hg_extend_closure(G, [A, B, C, D], G1), hornguard_call(G1).
hornguard_call(G, A, B, C, D, E) :- hg_extend_closure(G, [A, B, C, D, E], G1), hornguard_call(G1).
hornguard_call(G, A, B, C, D, E, F) :- hg_extend_closure(G, [A, B, C, D, E, F], G1), hornguard_call(G1).
hornguard_call(G, A, B, C, D, E, F, H) :- hg_extend_closure(G, [A, B, C, D, E, F, H], G1), hornguard_call(G1).

%   An unbound goal must stay unbound so the judge refuses it as such; the
%   `M:G` pattern would otherwise unify with it and never stop stripping.
hg_strip_module(V, hornguard, V) :- var(V), !.
hg_strip_module(M:G0, M, G) :- !,
    hg_strip_inner(G0, G).
hg_strip_module(G, hornguard, G).

hg_strip_inner(V, V) :- var(V), !.
hg_strip_inner(_:G0, G) :- !, hg_strip_inner(G0, G).
hg_strip_inner(G, G).

%   An unbound closure stays unbound: the judge refuses it as such.
hg_extend_closure(V, _, V) :- var(V), !.
hg_extend_closure(M:C, Extra, M:G) :- !, hg_extend_closure(C, Extra, G).
hg_extend_closure(C, Extra, G) :-
    callable(C), !,
    C =.. L0, append(L0, Extra, L), G =.. L.
hg_extend_closure(C, _, C).

%   A goal still unbound when its sink runs is refused here, not judged: the
%   judged-mode rewrite would wrap it in another hornguard_call/1 and the
%   two would hand it back and forth without end.
hg_runtime_judge(V, refused(instantiation_error, escape_attempt, unbound_goal)) :-
    var(V), !.
hg_runtime_judge(G, Verdict) :-
    (   catch(runtime_judge_hook(G, V0), _, fail)
    ->  Verdict = V0
    ;   hornguard_policy(policy(B, Ps, Os, Al, Tr)),
        hg_runtime_options(Ro),
        ( memberchk(profiles(Ps1), Ro) -> true ; Ps1 = Ps ),
        ( memberchk(allow(Al1), Ro) -> true ; Al1 = Al ),
        ( memberchk(trust(Tr1), Ro) -> true ; Tr1 = Tr ),
        hornguard_admit(B, Ps1, G, [allow(Al1), trust(Tr1), dynamic_dispatch(judged)|Os], Verdict)
    ).

hg_runtime_proceed(admit, M, G) :- !,
    call(M:G).
hg_runtime_proceed(admit_with(Guarded), M, _) :- !,
    call(M:Guarded).
hg_runtime_proceed(admit_needs(Needs), _, G) :- !,
    ( callable(G) -> functor(G, N, A), Ind = N/A ; Ind = G ),
    throw(error(permission_error(execute, goal, Ind), hornguard(benign_miss, runtime(needs(Needs))))).
hg_runtime_proceed(refused(Reason, Class, Rule), _, _) :-
    throw(error(Reason, hornguard(Class, runtime(Rule)))).

%!  hornguard_set_runtime_context(+Options) is det.
%
%   What hornguard_call/N judges under, beyond the loaded policy:
%   profiles(Names), allow(Indicators), trust(Pairs). A host sets this for
%   the namespace whose rules are about to run, from a position the author
%   cannot reach; the setter is not in any profile.

hornguard_set_runtime_context(Options) :-
    must_be(list, Options),
    nb_setval('$hornguard_runtime_context', Options).

hg_runtime_options(Options) :-
    (   nb_current('$hornguard_runtime_context', O), is_list(O)
    ->  Options = O
    ;   Options = []
    ).

%!  hornguard_catch(:Goal, ?Catcher, :Recovery) is nondet.
%
%   catch/3 as a stored rule gets it: a runtime refusal, a time limit, a
%   resource error and an execute permission error pass straight through,
%   so a catch-all recovery cannot hide that a goal was refused or keep a
%   query running past its budget.

hornguard_catch(Goal, Catcher, Recovery) :-
    catch(Goal, Ball,
          (   hg_uncatchable(Ball)
          ->  throw(Ball)
          ;   Catcher = Ball
          ->  call(Recovery)
          ;   throw(Ball)
          )).

%   Guarded on the context being bound: an author's own throw(error(X, _))
%   carries an unbound one and must stay catchable.
hg_uncatchable(error(_, Ctx)) :- nonvar(Ctx), Ctx = hornguard(_, _).
hg_uncatchable(time_limit_exceeded).
hg_uncatchable(error(resource_error(_), _)).
hg_uncatchable(error(permission_error(execute, _, _), _)).


		 /*******************************
		 *      NOT YET IMPLEMENTED     *
		 *******************************/

%!  hornguard_run(+Backend, +Profiles, +Caps, +Goal)
%
%   Not yet implemented, and it refuses before it gets that far on any
%   backend that cannot bound a running goal. A judge-only backend has no
%   caps, no isolation and no uncatchable abort: admitting a goal there and
%   running it anyway is the mistake this predicate exists to prevent.

hornguard_run(Backend, _Profiles, _Caps, _Goal) :-
    hg_ensure_profiles,
    must_be(atom, Backend),
    (   hg_enforcement(Backend, native)
    ->  throw(error(not_implemented(hornguard_run/4), _))
    ;   hg_enforcement(Backend, external)
    ->  throw(error(permission_error(run, backend, Backend),
                    context(hornguard_run/4,
                            'this backend has no in-engine caps; the host must bound the engine from outside and run the goal itself')))
    ;   throw(error(permission_error(run, backend, Backend),
                    context(hornguard_run/4,
                            'judge-only backend: it can say whether a goal is admissible, not run it safely')))
    ).
