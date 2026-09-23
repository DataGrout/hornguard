:- module(hornguard_judge_files, [ judge_files/1, judge_files/2 ]).

%% Judge Prolog source files as a host would judge a library it is about to
%% install: every clause under the shipped profiles, then the file as a
%% program. For each file, the count of clauses, the program verdict, and
%% every distinct refusal with how often it occurred, so a library author
%% sees at once what would keep their work out of a sandboxed engine.
%%
%%   swipl -q -g "judge_files(['modules/duty/duty.pl'])" -t halt tools/judge_files.pl
%%   swipl -q -g "judge_files(Files, [dynamic_dispatch(judged)])" ...
%%
%% Directives other than dynamic/1 and discontiguous/1 are reported, not
%% judged; a battery's `battery_*` manifest facts are skipped. The file's own
%% heads and its dynamic declarations are allowed, as they would be once
%% installed, and cross-file references are deferred rather than refused.

:- use_module(library(lists)).
:- use_module(library(apply)).
:- use_module('../prolog/hornguard').

judge_files(Files) :-
    judge_files(Files, []).

judge_files(Files, Options) :-
    hornguard_profiles(All),
    exclude(==(hornguard_runtime), All, Profiles),
    forall(member(F, Files), judge_file(F, Profiles, Options)).

judge_file(F, Profiles, Options) :-
    read_terms(F, Terms),
    classify(Terms, Clauses, Dyn, Other),
    heads(Clauses, Heads),
    append(Heads, Dyn, Allow0), sort(Allow0, Allow),
    Opts = [allow(Allow), defer_unknown(true)|Options],
    findall(Rule-Class,
            ( member(C, Clauses),
              hornguard_admit_clause(swi, Profiles, C, Opts, refused(_, Class, Rule0)),
              ( Rule0 = R + depth(_) -> Rule = R ; Rule = Rule0 ) ),
            Refusals0),
    msort(Refusals0, Refusals1),
    clumped(Refusals1, Refusals),
    catch(hornguard_admit_program(swi, Profiles, Clauses, Opts, PV), E, PV = exception(E)),
    length(Clauses, NC),
    file_base_name(F, Base),
    short(PV, PVS),
    format("~w~t~28|~d clauses  program: ~w~n", [Base, NC, PVS]),
    forall(member(Rule-Class-N, Refusals), format("~t~30|~w x ~w (~w)~n", [N, Rule, Class])),
    forall(member(O, Other), format("~t~30|not judged: ~q~n", [O])).

read_terms(F, Terms) :-
    setup_call_cleanup(open(F, read, In), read_all(In, Terms), close(In)).

read_all(In, Terms) :-
    catch(read_term(In, T, [module(hornguard_judge_files)]), E, T = read_error(E)),
    (   T == end_of_file -> Terms = []
    ;   Terms = [T|Rest], read_all(In, Rest)
    ).

classify([], [], [], []).
classify([T|Ts], Cs, Ds, Os) :-
    (   T = (:- dynamic(Spec)) -> dyn_inds(Spec, Inds), append(Inds, Ds1, Ds), Cs = Cs1, Os = Os1
    ;   T = (:- discontiguous(_)) -> Cs = Cs1, Ds = Ds1, Os = Os1
    ;   T = (:- _) -> Os = [T|Os1], Cs = Cs1, Ds = Ds1
    ;   T = read_error(E) -> Os = [read_error(E)|Os1], Cs = Cs1, Ds = Ds1
    ;   manifest_fact(T) -> Cs = Cs1, Ds = Ds1, Os = Os1
    ;   Cs = [T|Cs1], Ds = Ds1, Os = Os1
    ),
    classify(Ts, Cs1, Ds1, Os1).

manifest_fact(T) :-
    compound(T), functor(T, Name, _),
    sub_atom(Name, 0, _, _, battery_).

dyn_inds((A, B), Inds) :- !, dyn_inds(A, IA), dyn_inds(B, IB), append(IA, IB, Inds).
dyn_inds([H|T], Inds) :- !, dyn_inds(H, IH), dyn_inds(T, IT), append(IH, IT, Inds).
dyn_inds([], []) :- !.
dyn_inds(N/A, [N/A]) :- !.
dyn_inds(_, []).

heads(Clauses, Heads) :-
    findall(N/A,
            ( member(C, Clauses),
              ( C = (H :- _) -> true ; H = C ),
              callable(H), H \= (_ --> _),
              functor(H, N, A) ),
            Hs0),
    sort(Hs0, Heads).

short(admit, admit) :- !.
short(admit_with(_), admit_with) :- !.
short(admit_needs(Ns), admit_needs(N)) :- !, length(Ns, N).
short(refused(_, C, R), refused(C, R)) :- !.
short(X, X).
