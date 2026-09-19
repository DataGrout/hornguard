%% The manifest-driven backends.
%%
%% `iso` and `swi` are shipped hand-written; `scryer` and `trealla` carry a
%% generated manifest of what their engine defines. A manifest never widens
%% anything: it changes the *reason* an unrecognised predicate is refused,
%% from an existence error to a permission error, and it stops
%% `defer_unknown` from deferring something the engine really has.

%% Pure goals are judged the same everywhere: the walk is engine-independent.
verdict(be_sc_pure,        scryer,  [iso, prologue], findall(X, member(X, [a, b]), _), admit).
verdict(be_tr_pure,        trealla, [iso, prologue], findall(X, member(X, [a, b]), _), admit).
verdict(be_sc_unbound,     scryer,  [iso], call(_), refused(escape_attempt, unbound_goal)).
verdict(be_tr_unbound,     trealla, [iso], call(_), refused(escape_attempt, unbound_goal)).
verdict(be_sc_nested_pin,  scryer,  [iso], findall(_, halt, _),
        refused(escape_attempt, pinned(process) + depth(1))).

%% Scryer really does expose these; the manifest records it and the pins
%% refuse them. This is the answer to "ISO engines are safe by construction":
%% a smaller builtin list is a smaller attack surface, not a sandbox.
verdict(be_sc_shell,       scryer,  [iso], shell(x), refused(capability_probe, pinned(process))).
verdict(be_sc_use_module,  scryer,  [iso], use_module(library(os)),
        refused(capability_probe, pinned(loading))).
verdict(be_sc_assertz,     scryer,  [iso], assertz(f), refused(capability_probe, pinned(database))).
verdict(be_sc_clause,      scryer,  [iso], clause(f, _), refused(reconnaissance, pinned(reflection))).
verdict(be_tr_shell,       trealla, [iso], shell(x), refused(capability_probe, pinned(process))).
verdict(be_tr_getenv,      trealla, [iso], getenv(h, _), refused(capability_probe, pinned(process))).
verdict(be_tr_consult,     trealla, [iso], consult(f), refused(capability_probe, pinned(loading))).
