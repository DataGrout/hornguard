%% Entry point for the judge worker process:
%%
%%     swipl prolog/hornguard_worker_main.pl
%%
%% Kept separate from the module so the module can be loaded as a library
%% without starting the stdio loop.
:- use_module(hornguard_worker).
:- initialization(hornguard_worker_main, main).
