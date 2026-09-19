:- module(hornguard_differential,
          [ differential/0,
            differential/1,             % +Profiles
            differential_report/2,      % +Profiles, -Report
            all_profiles/1              % -Profiles
          ]).

%% Enumeration differential against SWI-Prolog's library(sandbox).
%%
%% For every predicate the engine defines in `system` and in a set of
%% commonly loaded libraries, judge a maximally instantiated goal with
%% Hornguard on the `swi` backend and with sandbox:safe_goal/1, then
%% classify the pair:
%%
%%   hole_candidate  Hornguard admits, sandbox refuses. Each one is either
%%                   a wrong attestation in a profile or a case where
%%                   sandbox is stricter than it needs to be. Read them all.
%%   profile_todo    sandbox considers it safe, Hornguard does not know it.
%%                   The work list for engine profiles.
%%   agree_admit / agree_refuse
%%   undecided       sandbox threw an instantiation error even after
%%                   instantiation by meta spec; judged by hand.
%%
%% Run: swipl -g differential -t halt tools/differential.pl

:- use_module(library(lists)).
:- use_module(library(apply)).
:- use_module(library(sandbox)).
:- use_module(library(aggregate)).
:- use_module(library(strings)).
:- use_module(library(pairs)).
:- use_module(library(ordsets)).
:- use_module(library(assoc)).
:- use_module(library(yall)).
:- use_module(library(solution_sequences)).
:- use_module(library(occurs)).
:- use_module(library(terms)).
:- use_module(library(dif)).
:- use_module('../prolog/hornguard').

library_module(lists).
library_module(apply).
library_module(aggregate).
library_module(strings).
library_module(pairs).
library_module(ordsets).
library_module(assoc).
library_module(yall).
library_module(solution_sequences).
library_module(occurs).
library_module(terms).
library_module(error).
library_module(dif).

%!  all_profiles(-Profiles) is det.
%
%   Every profile the loaded policy knows about.
all_profiles(Profiles) :-
    hornguard_profiles(Profiles).

differential :-
    differential([iso, prologue]).

differential(Profiles) :-
    differential_report(Profiles, Report),
    forall(member(Kind, [hole_candidate, undecided, profile_todo]),
           ( include(of_kind(Kind), Report, Rows),
             length(Rows, N),
             format("~n== ~w (~d)~n", [Kind, N]),
             forall(member(_-Ind-Detail, Rows),
                    format("  ~q~t~40|~q~n", [Ind, Detail])) )),
    forall(member(Kind, [agree_admit, agree_refuse]),
           ( include(of_kind(Kind), Report, Rows),
             length(Rows, N),
             format("~n== ~w (~d)~n", [Kind, N]) )).

of_kind(Kind, K-_-_) :- K == Kind.

differential_report(Profiles, Report) :-
    findall(M-Ind, candidate(M, Ind), Cands0),
    sort(Cands0, Cands),
    findall(Kind-Ind-Detail,
            ( member(M-Ind, Cands),
              classify(M, Ind, Profiles, Kind, Detail) ),
            Report).

candidate(system, N/A) :-
    current_predicate(system:N/A),
    \+ sub_atom(N, 0, _, _, '$'),
    functor(H, N, A),
    predicate_property(system:H, defined),
    \+ predicate_property(system:H, imported_from(_)).
candidate(M, N/A) :-
    library_module(M),
    current_predicate(M:N/A),
    \+ sub_atom(N, 0, _, _, '$'),
    functor(H, N, A),
    predicate_property(M:H, defined),
    \+ predicate_property(M:H, imported_from(_)),
    predicate_property(M:H, exported).

classify(M, N/A, Profiles, Kind, Detail) :-
    functor(G0, N, A),
    instantiate(M:G0, G),
    (   sub_term(S, G), S == '$hg_unfillable'
    ->  Kind = undecided, Detail = closure_arity_above_2
    ;   hornguard_admit(swi, Profiles, G, HV),
        sandbox_verdict(M:G, SV),
        kind(HV, SV, Kind),
        Detail = hg(HV)-sb(SV)
    ).

kind(admit, safe, agree_admit) :- !.
kind(admit_needs(_), safe, agree_admit) :- !.
kind(admit, unsafe(_), hole_candidate) :- !.
kind(admit_needs(_), unsafe(_), hole_candidate) :- !.
kind(admit, undecided, undecided) :- !.
kind(admit_needs(_), undecided, undecided) :- !.
kind(refused(_, _, _), safe, profile_todo) :- !.
kind(refused(_, _, _), _, agree_refuse).

sandbox_verdict(MG, V) :-
    catch(( sandbox:safe_goal(MG) -> V = safe ; V = unsafe(failed) ),
          E,
          sandbox_exception(E, V)).

sandbox_exception(error(instantiation_error, _), undecided) :- !.
sandbox_exception(error(Formal, _), unsafe(Formal)) :- !.
sandbox_exception(E, unsafe(E)).

%   Fill goal-taking arguments with something sandbox can judge, so the
%   comparison is about the predicate rather than about an unbound
%   argument.
instantiate(M:G0, G) :-
    (   catch(predicate_property(M:G0, meta_predicate(Spec)), _, fail)
    ->  G0 =.. [N|Args0], Spec =.. [_|Modes],
        maplist(fill_arg, Modes, Args0, Args),
        G =.. [N|Args]
    ;   G = G0
    ).

fill_arg(0, _, true) :- !.
fill_arg(^, _, true) :- !.
fill_arg(//, _, []) :- !.
fill_arg(1, _, =(a)) :- !.
fill_arg(2, _, (=)) :- !.
%   No profile-allowed predicate exists at every arity above 2, so a
%   closure that needs three or more extra arguments cannot be filled with
%   something both judges would accept. Mark it and report as undecided.
fill_arg(K, _, '$hg_unfillable') :- integer(K), K > 2, !.
fill_arg(_, A, A).
