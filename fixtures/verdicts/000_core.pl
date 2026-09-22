%% Core verdict fixtures: the structural rules of the judge, independent of any
%% engine. The denied exemplar throughout is current_prolog_flag/2 (pinned
%% class flags_ops): pure-looking, harmless in isolation, and the predicate
%% behind a real install-path leak.

%% Pure goals under iso are admitted.
verdict(core_admit_unify,      iso, [iso], (A = f(B), B == a, A == f(a)), admit).
verdict(core_admit_arith,      iso, [iso], (X is 1 + 2, X > 2), admit).
verdict(core_admit_findall,    iso, [iso], findall(X, atom(X), _), admit).

%% A goal that needs a profile the host has not loaded is admissible once it does.
verdict(core_needs_prologue,   iso, [iso], findall(X, member(X, [a, b]), _), admit_needs([profile(prologue)])).

%% An unbound goal in call position is never admitted.
verdict(core_unbound_call,     iso, [iso], call(_G), refused(escape_attempt, unbound_goal)).
verdict(core_unbound_findall,  iso, [iso], findall(_X, _G, _L), refused(escape_attempt, unbound_goal)).
verdict(core_constructed_call, iso, [iso], (G =.. [current_prolog_flag, home, _], call(G)),
        refused(escape_attempt, unbound_goal)).

%% A pinned predicate is refused at the top level as a probe...
verdict(core_pinned_top,       iso, [iso], current_prolog_flag(home, _),
        refused(capability_probe, pinned(flags_ops))).

%% ...and inside a meta-argument as an escape attempt, carrying its depth.
verdict(core_pinned_nested_1,  iso, [iso], findall(H, current_prolog_flag(home, H), _),
        refused(escape_attempt, pinned(flags_ops) + depth(1))).
verdict(core_pinned_nested_2,  iso, [iso], forall(true, \+ current_prolog_flag(home, _)),
        refused(escape_attempt, pinned(flags_ops) + depth(2))).
verdict(core_pinned_in_catch,  iso, [iso], catch(true, _, current_prolog_flag(home, _)),
        refused(escape_attempt, pinned(flags_ops) + depth(1))).

%% Closures are completed to full arity before judging.
verdict(core_closure_pinned,   iso, [iso, prologue], maplist(current_prolog_flag(home), [_]),
        refused(escape_attempt, pinned(flags_ops) + depth(1))).

%% A predicate from a profile not in force is admissible once the host loads it.
verdict(core_profile_miss,     iso, [iso], append([a], [b], _), admit_needs([profile(prologue)])).
verdict(core_profile_hit,      iso, [iso, prologue], append([a], [b], _), admit).

%% An unknown predicate is a benign miss with an existence reason.
verdict(core_unknown,          iso, [iso], no_such_predicate(_),
        refused(benign_miss, unknown)).

%% Module qualification is refused in every form: the sandbox has one module.
verdict(core_qualified_system,   iso, [iso], system:true, refused(escape_attempt, qualified)).
verdict(core_qualified_var,      iso, [iso], _M:true, refused(escape_attempt, qualified)).
verdict(core_qualified_nested,   iso, [iso], findall(_, user:atom(a), _), refused(escape_attempt, qualified)).
verdict(core_qualified_closure,  iso, [iso, prologue], maplist(system:atom, [a]), refused(escape_attempt, qualified)).

%% Reflection is reconnaissance at any depth.
verdict(core_recon_top,          iso, [iso], current_predicate(_), refused(reconnaissance, pinned(reflection))).
verdict(core_recon_nested,       iso, [iso], findall(P, current_predicate(P), _),
        refused(reconnaissance, pinned(reflection) + depth(1))).

%% Existential qualification inside bagof/setof is walked through.
verdict(core_setof_caret,        iso, [iso], setof(X, Y^atom_length(X, Y), _), admit).
verdict(core_setof_caret_pinned, iso, [iso], setof(X, Y^current_prolog_flag(X, Y), _),
        refused(escape_attempt, pinned(flags_ops) + depth(1))).

%% Non-callable terms in goal position.
verdict(core_not_callable,       iso, [iso], 42, refused(benign_miss, not_callable)).
verdict(core_not_callable_arg,   iso, [iso], call(42), refused(benign_miss, not_callable)).

%% Negation as failure is a meta-argument in both spellings and counts depth
%% identically: \+/1 from iso, not/1 from prologue.
verdict(core_naf_iso,            iso, [iso], \+ current_prolog_flag(home, _),
        refused(escape_attempt, pinned(flags_ops) + depth(1))).
verdict(core_naf_not,            iso, [iso, prologue], not(current_prolog_flag(home, _)),
        refused(escape_attempt, pinned(flags_ops) + depth(1))).
verdict(core_naf_not_needs,      iso, [iso], not(atom(a)), admit_needs([profile(prologue)])).
verdict(core_naf_not_pure,       iso, [iso, prologue], not(atom(a)), admit).

%% Closure completion. A closure argument is not a goal as written: it is a
%% goal missing its last N arguments, and the meta spec says how many. The
%% judge completes it with fresh variables before judging, so a closure whose
%% completed form is refused is refused. Without this rule the whole
%% allowlist is bypassable by partial application.
verdict(core_closure_1_completed,  iso, [iso, prologue], maplist(current_prolog_flag(home), [_]),
        refused(escape_attempt, pinned(flags_ops) + depth(1))).
verdict(core_closure_2_completed,  iso, [iso, prologue], foldl(current_prolog_flag, [home], 0, _),
        refused(escape_attempt, pinned(flags_ops) + depth(1))).
verdict(core_closure_include,      iso, [iso, prologue], include(current_prolog_flag, [home], _),
        refused(escape_attempt, pinned(flags_ops) + depth(1))).
verdict(core_closure_exclude,      iso, [iso, prologue], exclude(current_prolog_flag, [home], _),
        refused(escape_attempt, pinned(flags_ops) + depth(1))).
verdict(core_closure_bare_atom,    iso, [iso, prologue], maplist(halt, [_]),
        refused(escape_attempt, pinned(process) + depth(1))).
verdict(core_closure_pure_ok,      iso, [iso, prologue], maplist(atom_length(abc), [_]), admit).
verdict(core_closure_unbound,      iso, [iso, prologue], maplist(_G, [a]),
        refused(escape_attempt, unbound_goal)).

%% The same rule through call/N, where the extra arguments are explicit.
verdict(core_call_n_completed,     iso, [iso], call(current_prolog_flag, home, _),
        refused(escape_attempt, pinned(flags_ops) + depth(1))).
verdict(core_call_n_pure,          iso, [iso], call(atom_length, abc, _), admit).

%% Arithmetic is a second language the walk looks into: the evaluables that
%% read the clock are pinned as `timing`, at the depth of the arithmetic goal.
%% Everything else in an expression is data.
verdict(core_evaluable_cputime,    iso, [iso], _ is cputime,
        refused(capability_probe, evaluable(cputime/0))).
verdict(core_evaluable_realtime,   iso, [iso], 0 < realtime,
        refused(capability_probe, evaluable(realtime/0))).
verdict(core_evaluable_nested,     iso, [iso], _ is 1 + max(2, cputime),
        refused(capability_probe, evaluable(cputime/0))).
verdict(core_evaluable_in_meta,    iso, [iso], findall(T, T is realtime, _),
        refused(escape_attempt, evaluable(realtime/0) + depth(1))).
verdict(core_evaluable_pure,       iso, [iso], (_ is 2 ** 10 + max(1, 2), 3 =:= 1 + 2), admit).
verdict(core_evaluable_as_data,    iso, [iso], _ = cputime, admit).

%% A coroutine runs its goal at a later unification, in whoever's code path
%% performs it. The goal would be judged; the moment would not. Pinned.
verdict(core_pinned_freeze,        iso, [iso], freeze(X, atom(X)),
        refused(capability_probe, pinned(deferred_execution))).
verdict(core_pinned_when_nested,   iso, [iso], findall(X, when(ground(X), atom(X)), _),
        refused(escape_attempt, pinned(deferred_execution) + depth(1))).

%% State one author sets and another author's query reads.
verdict(core_pinned_set_random,    iso, [iso], set_random(seed(1)),
        refused(capability_probe, pinned(shared_state))).
verdict(core_pinned_tables,        iso, [iso], abolish_all_tables,
        refused(capability_probe, pinned(shared_state))).
