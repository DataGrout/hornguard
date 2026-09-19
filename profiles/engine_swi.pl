%% Enforcement for the SWI backend.
%%
%% There is no `engine(swi, _)` manifest: on SWI the judge asks the engine
%% directly through predicate_property/2, which is better than a snapshot
%% because it cannot go stale against the running system.
%%
%% SWI gives a host what the judge cannot: call_with_time_limit/2,
%% call_with_inference_limit/3, a per-call stack limit, per-tenant modules,
%% protect_static_code, and a time-limit exception the author's own catch/3
%% cannot swallow. That is what `native` claims.
enforcement(swi, native).

%% `iso` is the base every backend inherits. ISO defines no caps, no
%% isolation and no uncatchable abort, so a host that judges under `iso` has
%% to run under something else.
enforcement(iso, none).
