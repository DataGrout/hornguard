%% Profile `hornguard_runtime`: the calls the judge's own rewrite introduces
%% under dynamic_dispatch(judged). Joined to the profiles in force
%% automatically in that mode; a host never lists it.
%%
%% hornguard_call/N judges its goal at the moment it runs, so to the static
%% judge its arguments are data: whatever they turn out to be is judged
%% then, under the same policy. hornguard_catch/3 is catch/3 that cannot
%% swallow a runtime refusal; its goal arguments are judged statically like
%% catch/3's. Because these are in a profile, no stored clause may define
%% them.

:- multifile allow/2, meta_spec/2.

allow(hornguard_runtime, hornguard_call/1).
allow(hornguard_runtime, hornguard_call/2).
allow(hornguard_runtime, hornguard_call/3).
allow(hornguard_runtime, hornguard_call/4).
allow(hornguard_runtime, hornguard_call/5).
allow(hornguard_runtime, hornguard_call/6).
allow(hornguard_runtime, hornguard_call/7).
allow(hornguard_runtime, hornguard_call/8).
allow(hornguard_runtime, hornguard_catch/3).

meta_spec(hornguard_runtime, hornguard_call(?)).
meta_spec(hornguard_runtime, hornguard_call(?, ?)).
meta_spec(hornguard_runtime, hornguard_call(?, ?, ?)).
meta_spec(hornguard_runtime, hornguard_call(?, ?, ?, ?)).
meta_spec(hornguard_runtime, hornguard_call(?, ?, ?, ?, ?)).
meta_spec(hornguard_runtime, hornguard_call(?, ?, ?, ?, ?, ?)).
meta_spec(hornguard_runtime, hornguard_call(?, ?, ?, ?, ?, ?, ?)).
meta_spec(hornguard_runtime, hornguard_call(?, ?, ?, ?, ?, ?, ?, ?)).
meta_spec(hornguard_runtime, hornguard_catch(0, ?, 0)).
