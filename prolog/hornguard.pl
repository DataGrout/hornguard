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
            hornguard_run/4,            % +Backend, +Profiles, +Caps, +Goal
            hornguard_load_profiles/1,  % +Dir
            hornguard_load_policy/1,    % +File
            hornguard_policy/1,         % -Policy
            hornguard_admit/2,          % +Goal, -Verdict        (under the loaded policy)
            hornguard_admit_clause/2,   % +Clause, -Verdict
            hornguard_admit_program/2,  % +Clauses, -Verdict
            hornguard_profiles/1        % -Names
          ]).

/** <module> Hornguard: default-deny firewall for untrusted Prolog

The judge. Pure: it never executes the term it is given. It walks a goal or a
clause, consults the loaded profiles (allow/2, meta_spec/2) and the pinned
class table (pinned/2), and returns a verdict:

  * `admit`
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
            | unstratified(Members, Head-Callee) | floundering(NegatedGoal)
            | cyclic_term | term_depth
              A pinned rule nested inside a meta-argument carries `+ depth(N)`.

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

Rewrites and enforcement (hornguard_rewrite/3, hornguard_run/4) are not yet
implemented; they belong to the backend layer, not the judge.
*/

:- use_module(library(lists)).
:- use_module(library(apply)).
:- use_module(library(error)).

:- dynamic hg_allow/2,          % Profile, Name/Arity
           hg_meta/2,           % Profile, Spec (meta_predicate notation)
           hg_pinned/2,         % Class, Name/Arity (Arity may be unbound)
           hg_engine/2,         % Backend, Name/Arity   (what the engine defines)
           hg_enforcement/2,    % Backend, native | external | none
           hg_loaded_dir/1,
           hg_default_dir/1.

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
%   pinned(Class, Name/Arity), engine(Backend, Name/Arity),
%   enforcement(Backend, Kind) and directives (ignored). Anything else is a
%   domain_error. An allow that names a pinned indicator is a load error:
%   pinned classes are not reopened by profile.

hornguard_load_profiles(DirOrDirs) :-
    (   is_list(DirOrDirs) -> Dirs = DirOrDirs ; Dirs = [DirOrDirs] ),
    must_be(list(atom), Dirs),
    retractall(hg_allow(_, _)),
    retractall(hg_meta(_, _)),
    retractall(hg_pinned(_, _)),
    retractall(hg_engine(_, _)),
    retractall(hg_enforcement(_, _)),
    retractall(hg_loaded_dir(_)),
    forall(member(Dir, Dirs), hg_load_profile_dir(Dir)),
    hg_check_policy,
    assertz(hg_loaded_dir(Dirs)).

hg_load_profile_dir(Dir) :-
    directory_files(Dir, Entries),
    include(hg_profile_file, Entries, Files0),
    msort(Files0, Files),
    forall(member(F, Files),
           ( directory_file_path(Dir, F, Path),
             hg_load_profile_file(Path) )).

hg_profile_file(F) :-
    file_name_extension(_, pl, F).

hg_load_profile_file(Path) :-
    setup_call_cleanup(
        open(Path, read, In),
        hg_read_profile_terms(In, Path),
        close(In)).

hg_read_profile_terms(In, Path) :-
    read_term(In, Term, [module(hornguard)]),
    (   Term == end_of_file
    ->  true
    ;   hg_accept_profile_term(Term, Path),
        hg_read_profile_terms(In, Path)
    ).

hg_accept_profile_term(allow(P, N/A), _) :-
    atom(P), atom(N), integer(A), !,
    assertz(hg_allow(P, N/A)).
hg_accept_profile_term(meta_spec(P, Spec), _) :-
    atom(P), callable(Spec), !,
    assertz(hg_meta(P, Spec)).
hg_accept_profile_term(pinned(C, N/A), _) :-
    atom(C), atom(N), ( var(A) ; integer(A) ), !,
    assertz(hg_pinned(C, N/A)).
hg_accept_profile_term(engine(B, N/A), _) :-
    atom(B), atom(N), integer(A), !,
    assertz(hg_engine(B, N/A)).
hg_accept_profile_term(enforcement(B, Kind), _) :-
    atom(B), hg_enforcement_kind(Kind), !,
    assertz(hg_enforcement(B, Kind)).
hg_accept_profile_term((:- _), _) :- !.
hg_accept_profile_term(Term, Path) :-
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

hg_check_policy :-
    forall(hg_allow(P, N/A),
           (   hg_pinned(C, N/A)
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

:- dynamic hg_policy/1.          % policy(Backend, Profiles, Options, Allow, Trust)
:- dynamic hg_unpinned/2.        % Class, Name/Arity  (kept for re-pinning)

hg_install_policy(Terms, File) :-
    hg_repin_all,
    forall(member(unpin(C), Terms), hg_unpin(C, File)),
    foldl(hg_policy_term(File), Terms, pol(iso, [iso], [], [], []), pol(B, Ps, Os, Al, Tr)),
    hg_check_host_allows(Al, File),
    retractall(hg_policy(_)),
    assertz(hg_policy(policy(B, Ps, Os, Al, Tr))).

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

hg_check_host_allows(Allows, File) :-
    forall(member(Ind, Allows),
           (   hg_pinned(C, Ind)
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

hornguard_admit(Backend, Profiles, Goal0, Options, Verdict) :-
    hg_ensure_profiles,
    hg_context(Backend, Profiles, Options, Ctx),
    hg_strict_negation(Options, Strict),
    hg_judged(Goal0, Goal,
              ( hg_goal(Goal, 0, Ctx, [], Needs0),
                hg_check_floundering(Strict, Goal),
                hg_needs_verdict(Needs0, Verdict) ),
              Verdict).

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

hornguard_admit_clause(Backend, Profiles, Clause0, Options, Verdict) :-
    hg_ensure_profiles,
    hg_context(Backend, Profiles, Options, Ctx),
    hg_strict_negation(Options, Strict),
    hg_judged(Clause0, Clause,
              ( hg_clause(Clause, Ctx, Needs0),
                hg_check_floundering(Strict, Clause),
                hg_needs_verdict(Needs0, Verdict) ),
              Verdict).

hg_needs_verdict([], admit) :- !.
hg_needs_verdict(Needs0, admit_needs(Needs)) :-
    sort(Needs0, Needs).

hg_context(Backend, Profiles, Options, ctx(Backend, Profiles, Allow, Trust, Defer)) :-
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
    ).

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
    hg_indicator(G, Name/Arity, D, Ctx, N0, N).
hg_goal(G, _, _, _, _) :-
    throw(hg_refused(type_error(callable, G), benign_miss, not_callable)).

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
    ;   hg_deferrable(Ctx, G)
    ->  N = [predicate(Ind)|N0]
    ;   hg_unknown_reason(Ctx, G, Ind, Reason),
        throw(hg_refused(Reason, benign_miss, unknown))
    ).

%   Under defer_unknown(true) an indicator the engine does not define is a
%   sandboxed predicate the host has not stored yet. It is reported as a
%   need rather than refused, so a rule may be stored before the rules it
%   calls. An indicator the engine does define but no profile allows stays
%   a refusal: deferral never widens the engine surface.
hg_deferrable(ctx(Backend, _, _, _, true), G) :-
    \+ hg_engine_defined(Backend, G).

hg_engine_defined(swi, G) :-
    catch(predicate_property(G, defined), _, fail).

%   Reflection is reconnaissance wherever it appears. Any other pinned
%   class is a probe at the top level and an escape attempt once it is
%   hidden inside a meta-argument: the author expected the outer goal to
%   pass.
hg_pinned_report_class(reflection, _, reconnaissance) :- !.
hg_pinned_report_class(_, 0, capability_probe) :- !.
hg_pinned_report_class(_, _, escape_attempt).

hg_depth_rule(Rule, 0, Rule) :- !.
hg_depth_rule(Rule, D, Rule + depth(D)).

hg_trusted(Ind, ctx(_, _, _, Trust, _), Spec) :-
    memberchk(Ind-Spec, Trust).

hg_in_force(Ind, ctx(_, Profiles, Allow, _, _)) :-
    (   member(P, Profiles), hg_allow(P, Ind)
    ->  true
    ;   memberchk(Ind, Allow)
    ).

hg_spec_in_force(Name/Arity, ctx(_, Profiles, _, _, _), Spec) :-
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
    hg_head(Head),
    hg_allow_head_in_body(Head, Ctx0, Ctx),
    hg_goal(Body, 0, Ctx, [], Needs).
hg_clause(Head, _, []) :-
    hg_head(Head).

%   A clause may call its own head: recursion is the normal shape of a rule.
%   Any other sandboxed predicate has to arrive through the allow/1 option,
%   because only the host knows what else is stored.
hg_allow_head_in_body(Head, ctx(B, P, Allow, Trust, D), ctx(B, P, [Ind|Allow], Trust, D)) :-
    functor(Head, Name, Arity),
    Ind = Name/Arity.

hg_head(Var) :-
    var(Var), !,
    throw(hg_refused(instantiation_error, escape_attempt, unbound_head)).
hg_head(_:_) :- !,
    throw(hg_refused(permission_error(modify, static_procedure, (:)/2), escape_attempt, head(qualified))).
hg_head(Head) :-
    callable(Head), !,
    functor(Head, Name, Arity),
    Ind = Name/Arity,
    (   hg_control_indicator(Ind)
    ->  throw(hg_refused(permission_error(modify, static_procedure, Ind), escape_attempt, head(control)))
    ;   hg_pinned(Class, Ind)
    ->  throw(hg_refused(permission_error(modify, static_procedure, Ind), escape_attempt, head(pinned(Class))))
    ;   hg_allow(Profile, Ind)
    ->  throw(hg_refused(permission_error(modify, static_procedure, Ind), escape_attempt, head(profile(Profile))))
    ;   true
    ).
hg_head(Head) :-
    throw(hg_refused(type_error(callable, Head), benign_miss, not_callable)).

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

hornguard_admit_program(Backend, Profiles, Clauses0, Options, Verdict) :-
    hg_ensure_profiles,
    must_be(list, Clauses0),
    hg_context(Backend, Profiles, Options, Ctx0),
    hg_strict_negation(Options, Strict),
    hg_judged(Clauses0, Clauses,
              ( hg_program_heads(Clauses, Heads),
                hg_allow_all(Heads, Ctx0, Ctx),
                foldl(hg_program_clause(Ctx), Clauses, [], Needs0),
                forall(member(C, Clauses), hg_check_floundering(Strict, C)),
                hg_check_stratified(Clauses),
                hg_needs_verdict(Needs0, Verdict) ),
              Verdict).

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

hg_allow_all(Inds, ctx(B, P, Allow0, Trust, D), ctx(B, P, Allow, Trust, D)) :-
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
    (   member(edge(H, C, neg), Edges),
        hg_reaches(C, H, Edges)
    ->  findall(P, ( member(P, Defined),
                     ( P == H ; hg_reaches(H, P, Edges), hg_reaches(P, H, Edges) ) ), Ms0),
        sort(Ms0, Members),
        Result = unstratified(Members, H-C)
    ;   hg_strata(Defined, Edges, Strata),
        Result = stratified(Strata)
    ).

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

%   Reachability over the dependency graph by at least one edge. Programs
%   stored in a namespace are small; a per-path visited list is enough.
hg_reaches(From, To, Edges) :-
    member(edge(From, Next, _), Edges),
    (   Next == To
    ->  true
    ;   hg_reach_from(Next, To, Edges, [From])
    ).

hg_reach_from(X, To, Edges, Visited) :-
    \+ memberchk(X, Visited),
    member(edge(X, Next, _), Edges),
    (   Next == To
    ->  true
    ;   hg_reach_from(Next, To, Edges, [X|Visited])
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
hg_engine_meta_gap(ctx(swi, _, _, _, _), G) :-
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
hg_engine_defines(ctx(swi, _, _, _, _), G, _) :- !,
    catch(predicate_property(G, defined), _, fail).
hg_engine_defines(ctx(Backend, _, _, _, _), _, Ind) :-
    hg_engine(Backend, Ind).


		 /*******************************
		 *      NOT YET IMPLEMENTED     *
		 *******************************/

hornguard_rewrite(_Backend, _Term, _Guarded) :-
    throw(error(not_implemented(hornguard_rewrite/3), _)).

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
