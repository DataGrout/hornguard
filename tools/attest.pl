:- module(hornguard_attest,
          [ attest/0,                 % every profile on this engine; fails on an unexpected impurity
            attest/1,                 % +Profiles | all
            attest_report/2,          % +Profiles | all, -Report
            attest_predicate/2        % +Indicator (Name/Arity or Module:Name/Arity), -Verdict
          ]).

%% Attestation by experiment.
%%
%% An `allow` line says a predicate is pure under adversarial use. The
%% differential checks that claim against another list; this checks it
%% against the engine. Every allowed predicate the running engine defines is
%% called under a handful of argument shapes, one solution, half a second
%% each, in a scratch directory, with tripwires around everything a pure
%% predicate has no business touching:
%%
%%   output        anything written to current output
%%   globals       nb_setval/b_setval state (keys and value hashes)
%%   flags         current_prolog_flag/2
%%   ops           the operator table
%%   streams       streams open before and after
%%   modules       the module list (a load, an assert into a new module)
%%   threads       threads alive
%%   records       the recorded database
%%   dynpreds      every dynamic predicate's clause count, in every module
%%   random        the random generator's state
%%   cwd, files    the working directory, and the files in the scratch one
%%
%% A wire that trips during a call to `true` is the harness's own noise and
%% is calibrated out. What remains is a change the predicate made, and a
%% predicate that makes one is `impure(Fired)` unless the profile declared it
%% (`expected/3`): `swi_random` admits randomness on purpose, and its
%% predicates move the generator's state. An `impure` verdict fails
%% attest/0, so it can gate CI on the engine it runs on.
%%
%% What this cannot see: effects outside the process (network, a file
%% written elsewhere than the scratch directory), effects on user_error, and
%% time. Those stay with the pins and the review. Errors and failures are
%% fine: purity is about what a call changes, not whether it succeeds.
%%
%%   swipl -q -g attest -t halt tools/attest.pl          (or: make attest)

:- use_module(library(lists)).
:- use_module(library(apply)).
:- use_module(library(time)).
:- use_module(library(yall)).
:- use_module('../prolog/hornguard').

%   The libraries the swi* profiles are generated from (tools/gen_swi_profiles.pl
%   names the same set), loaded so their predicates are visible here.
%   autoload_all/0 does not load every one of them.
:- use_module(library(random)).
:- use_module(library(aggregate)).
:- use_module(library(strings)).
:- use_module(library(pairs)).
:- use_module(library(ordsets)).
:- use_module(library(assoc)).
:- use_module(library(solution_sequences)).
:- use_module(library(occurs)).
:- use_module(library(terms)).
:- use_module(library(error)).
:- use_module(library(dif)).
:- use_module(library(sort)).
:- catch(use_module(library(backcomp)), _, true).

time_limit(0.5).

%   expected(Profile, Indicator, Why): an impurity the profile means.
expected(swi_random, _, random_state).

attest :-
    attest(all).

attest(Profiles) :-
    attest_report(Profiles, Report),
    print_report(Report),
    \+ memberchk(_-_-impure(_), Report).

%!  attest_report(+Profiles, -Report) is det.
%
%   Report is a list of Profile-Indicator-Verdict, Verdict one of `pure`,
%   `impure(Fired)`, `expected(Why, Fired)`, `skipped(Why)`. Fired is a list
%   of Shape-Wires, Wires a list of wire(Name, Detail).

attest_report(Profiles0, Report) :-
    hornguard_profiles(All),
    (   Profiles0 == all -> Profiles = All ; Profiles = Profiles0 ),
    findall(P-Ind, ( member(P, Profiles), hornguard:hg_allow(P, Ind) ), Pairs0),
    sort(Pairs0, Pairs),
    prime,
    in_scratch(( calibrate(Noise),
                 maplist(attest_pair(Noise), Pairs, Report) )).

%!  attest_predicate(+Spec, -Verdict) is det.
%
%   One predicate, for tests and for a profile author checking a line.

attest_predicate(Spec, Verdict) :-
    prime,
    in_scratch(( calibrate(Noise),
                 verdict(none, Spec, Noise, Verdict) )).

%   Autoloading a library during a call would trip the module and clause
%   wires (SWI's file-search cache is a dynamic predicate), and would be the
%   engine's doing rather than the predicate's. Load everything first.
prime :-
    catch(autoload_all, _, true).

%   Messages a predicate prints go to user_error, which the output wire does
%   not see. While a call runs, the hook below records them instead, under a
%   key the globals wire is told to ignore.
:- multifile user:message_hook/3.
user:message_hook(Term, Kind, _Lines) :-
    Kind \== silent,
    nb_current(hg_attest_msgs, Msgs),
    arg(1, Msgs, L),
    nb_setarg(1, Msgs, [Kind-Term|L]).

attest_pair(Noise, P-Ind, P-Ind-Verdict) :-
    verdict(P, Ind, Noise, Verdict).

verdict(P, Spec0, Noise, Verdict) :-
    (   resolve(Spec0, Spec)
    ->  findall(Shape-Wires,
                ( shape(Spec, Shape),
                  run_shape(Spec, Shape, Noise, Wires),
                  Wires \== [] ),
                Fired),
        (   Fired == []
        ->  Verdict = pure
        ;   spec_indicator(Spec, Ind), expected(P, Ind, Why)
        ->  Verdict = expected(Why, Fired)
        ;   Verdict = impure(Fired)
        )
    ;   Verdict = skipped(undefined)
    ).

spec_indicator(_:Ind, Ind) :- !.
spec_indicator(Ind, Ind).

%   Where the predicate lives. Visible from here, or in some module that
%   defines it (a library this module does not import: the swi_assoc or
%   swi_backcomp profiles), in which case the call is qualified with that
%   module, as the engine itself would resolve an author's call to it.
resolve(M:N/A, M:N/A) :- !,
    functor(H, N, A),
    catch(predicate_property(M:H, defined), _, fail).
resolve(N/A, N/A) :-
    functor(H, N, A),
    catch(predicate_property(H, defined), _, fail), !.
resolve(N/A, M:N/A) :-
    functor(H, N, A),
    current_module(M),
    catch(( predicate_property(M:H, defined),
            \+ predicate_property(M:H, imported_from(_)) ), _, fail), !.

%   Everything runs in a fresh directory so a file effect has somewhere to
%   land where the files wire will see it, and the directory is removed after.
in_scratch(Goal) :-
    tmp_file(hg_attest, Dir),
    make_directory(Dir),
    working_directory(Old, Dir),
    setup_call_cleanup(true,
                       Goal,
                       ( working_directory(_, Old),
                         catch(delete_directory_and_contents(Dir), _, true) )).

		 /*******************************
		 *            SHAPES            *
		 *******************************/

%   One shape per data value, each data argument taking that value, and
%   one mixed shape; goal arguments are `true`, closures a lambda that takes
%   the right number of arguments and does nothing. Errors are fine.
data_value(a).
data_value(1).
data_value("s").
data_value([a, b]).
data_value(f(x)).
data_value(_).

shape(Spec, Args) :-
    spec_indicator(Spec, N/A),
    modes(N/A, Modes),
    (   data_value(V), maplist(mode_arg(V), Modes, Args)
    ;   mixed_args(Modes, Args)
    ).

%   Control constructs have no meta spec because the judge walks through
%   them structurally; here their arguments are goals, since a data term in
%   one of those positions is not the predicate under test (on SWI a list in
%   goal position is consult/1, which the judge refuses on its own account).
modes((^)/2, [?, 0]) :- !.
modes(N/A, Modes) :-
    hornguard:hg_control_indicator(N/A), !,
    length(Modes, A), maplist(=(0), Modes).
modes(N/A, Modes) :-
    (   hornguard:hg_any_meta_spec(N/A, Spec)
    ->  Spec =.. [_|Modes]
    ;   length(Modes, A), maplist(=(?), Modes)
    ).

mode_arg(_, 0, true) :- !.
mode_arg(_, ^, true) :- !.
mode_arg(_, K, Lambda) :- integer(K), K > 0, !, length(Ps, K), Lambda = (Ps >> true).
mode_arg(V, _, V).

mixed_args(Modes, Args) :-
    findall(V, data_value(V), Vs0),
    exclude(var, Vs0, Vs),
    mixed_args(Modes, Vs, 0, Args).

mixed_args([], _, _, []).
mixed_args([M|Ms], Vs, I, [A|As]) :-
    (   ( M == 0 ; M == (^) )
    ->  A = true
    ;   integer(M), M > 0
    ->  length(Ps, M), A = (Ps >> true)
    ;   length(Vs, NV), J is I mod NV, nth0(J, Vs, A)
    ),
    I1 is I + 1,
    mixed_args(Ms, Vs, I1, As).

build_goal(M:N/_, Args, M:G) :- !, G =.. [N|Args].
build_goal(N/_, Args, G) :- G =.. [N|Args].

		 /*******************************
		 *          TRIPWIRES           *
		 *******************************/

run_shape(Spec, Args, Noise, Wires) :-
    build_goal(Spec, Args, Goal),
    time_limit(T),
    nb_setval(hg_attest_msgs, msgs([])),
    snapshot(Before),
    (   with_output_to(string(Out),
                       ( catch(call_with_time_limit(T, once(Goal)), _, true) -> true ; true ))
    ->  true
    ;   Out = ""
    ),
    snapshot(After),
    nb_getval(hg_attest_msgs, msgs(Msgs0)),
    nb_delete(hg_attest_msgs),
    diff(Before, After, [globals-hg_attest_msgs|Noise], Wires0),
    (   Out == "" -> Wires1 = Wires0
    ;   Wires1 = [wire(output, Out)|Wires0]
    ),
    (   Msgs0 == [] -> Wires = Wires1
    ;   reverse(Msgs0, Msgs), Wires = [wire(messages, Msgs)|Wires1]
    ).

snapshot([ globals-G, flags-F, ops-O, streams-S, modules-M, threads-T,
           records-R, random-Rn, dynpreds-D, cwd-C, files-Fi ]) :-
    findall(K-H, ( nb_current(K, V), value_hash(V, H) ), G0), msort(G0, G),
    findall(K-V, current_prolog_flag(K, V), F0), msort(F0, F),
    findall(op(P, Ty, N), current_op(P, Ty, N), O0), msort(O0, O),
    findall(St, stream_property(St, _), S0), sort(S0, S),
    findall(Mo, current_module(Mo), M0), sort(M0, M),
    findall(Th, thread_property(Th, status(_)), T0), sort(T0, T),
    findall(K, recorded(K, _, _), R0), msort(R0, R),
    (   catch(random_property(state(Rn0)), _, fail) -> Rn = Rn0 ; Rn = none ),
    findall(Mo:N/A-C,
            ( current_module(Mo),
              catch(( predicate_property(Mo:H, dynamic),
                      \+ predicate_property(Mo:H, imported_from(_)),
                      functor(H, N, A),
                      predicate_property(Mo:H, number_of_clauses(C)) ),
                    _, fail) ),
            D0),
    sort(D0, D),
    working_directory(C, C),
    directory_files('.', Fi0), sort(Fi0, Fi).

value_hash(V, H) :-
    copy_term(V, V1),
    numbervars(V1, 0, _),
    term_hash(V1, H).

%   Keyed components diff by key so noise can be ignored per key; the
%   rest diff whole.
keyed(globals).
keyed(flags).

diff(Before, After, Noise, Wires) :-
    findall(W, ( member(Name-B, Before), memberchk(Name-A, After),
                 component_wire(Name, B, A, Noise, W) ), Wires).

%   No lambda here: yall copies a lambda's free variables, so Noise would
%   arrive unbound and memberchk/2 would bind it, excluding every key.
component_wire(Name, B, A, Noise, wire(Name, keys(Keys))) :-
    keyed(Name), !,
    changed_keys(B, A, Keys0),
    exclude(noise_key(Name, Noise), Keys0, Keys),
    Keys \== [].
component_wire(Name, B, A, Noise, wire(Name, Detail)) :-
    \+ memberchk(Name-all, Noise),
    B \== A,
    (   is_list(B), is_list(A)
    ->  subtract(A, B, Added), subtract(B, A, Removed),
        Detail = changed(added(Added), removed(Removed))
    ;   Detail = changed(B, A)
    ).

noise_key(Name, Noise, K) :-
    memberchk(Name-K, Noise).

changed_keys(B, A, Keys) :-
    findall(K, ( member(K-V, A), \+ memberchk(K-V, B) ), K1),
    findall(K, ( member(K-_, B), \+ memberchk(K-_, A) ), K2),
    append(K1, K2, Keys0), sort(Keys0, Keys).

%   What trips during `true`, three times over, is the harness's own noise:
%   keyed components contribute the keys that moved, others their name.
calibrate(Noise) :-
    findall(N, ( between(1, 3, _),
                 run_shape(true/0, [], [], Wires),
                 member(wire(Name, Detail), Wires),
                 noise_entry(Name, Detail, N) ),
            Noise0),
    sort(Noise0, Noise).

noise_entry(Name, keys(Keys), Name-K) :- !, member(K, Keys).
noise_entry(Name, _, Name-all).

		 /*******************************
		 *            REPORT            *
		 *******************************/

print_report(Report) :-
    forall(member(P-Ind-V, Report), print_line(P, Ind, V)),
    aggregate_all(count, member(_-_-pure, Report), NPure),
    aggregate_all(count, member(_-_-impure(_), Report), NImp),
    aggregate_all(count, member(_-_-expected(_, _), Report), NExp),
    aggregate_all(count, member(_-_-skipped(_), Report), NSkip),
    current_prolog_flag(version_data, swi(Ma, Mi, Pa, _)),
    format("~n~d pure, ~d expected, ~d impure, ~d skipped, on SWI-Prolog ~w.~w.~w~n",
           [NPure, NExp, NImp, NSkip, Ma, Mi, Pa]).

print_line(_, _, pure) :- !.
print_line(_, _, skipped(_)) :- !.
print_line(P, Ind, expected(Why, Fired)) :- !,
    format("expected  ~w ~w  (~w)~n", [P, Ind, Why]),
    print_fired(Fired).
print_line(P, Ind, impure(Fired)) :-
    format("IMPURE    ~w ~w~n", [P, Ind]),
    print_fired(Fired).

print_fired(Fired) :-
    forall(member(Shape-Wires, Fired),
           ( format("    ~q~n", [Shape]),
             forall(member(wire(N, D), Wires),
                    ( term_to_atom(D, DA),
                      (   atom_length(DA, Len), Len > 160
                      ->  sub_atom(DA, 0, 160, _, DS)
                      ;   DS = DA
                      ),
                      format("      ~w: ~w~n", [N, DS]) )) )).
