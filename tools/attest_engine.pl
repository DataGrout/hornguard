:- module(hornguard_attest_engine,
          [ attest_engines/0,          % every engine on PATH; fails on an undeclared impurity
            attest_engine/1,           % +Backend (scryer | trealla)
            attest_engine_report/2,    % +Backend, -Report
            attest_engine_report/3,    % +Backend, +Indicators, -Report
            attest_engine_goals/3,     % +Backend, +[Id-Goal], -[Id-Verdict]
            engine_available/1         % ?Backend
          ]).

%% Attestation by experiment, inside the other engines.
%%
%% tools/attest.pl runs inside SWI and can only attest what SWI defines. The
%% Scryer and Trealla backends carry manifests instead, and an allow line is
%% a claim about *that* engine's predicate, which may be a different
%% implementation. So the same experiment runs inside each engine: for every
%% allowed predicate the engine's manifest says it defines, a self-contained
%% strict-ISO probe is generated and run in that engine, one process per
%% predicate, with the tripwires the engine can express:
%%
%%   output     anything written to current output (redirected to a file)
%%   flags      current_prolog_flag/2          ops     current_op/3
%%   streams    stream_property/2              preds   current_predicate/1
%%   dynclauses clause counts of every dynamic predicate
%%   files      the scratch directory's files (where the engine can list them)
%%
%% The engine's own noise is calibrated out against `true`, as in SWI. A
%% predicate that hangs is killed by this side after twenty seconds and
%% reported as `timeout`, not impure. What these engines cannot report
%% (global variables, threads, the random state) stays with the review.
%%
%%   swipl -q -g attest_engines -t halt tools/attest_engine.pl     (make attest-engines)

:- use_module(library(lists)).
:- use_module(library(apply)).
:- use_module(library(aggregate)).
:- use_module(library(process)).
:- use_module(library(readutil)).
:- use_module('../prolog/hornguard').

engine_binary(scryer, path('scryer-prolog')).
engine_binary(trealla, path(tpl)).

process_timeout(20).

%   expected(Backend, Indicator, Why): an impurity declared for that engine.
expected(_, _, _) :- fail.

engine_available(B) :-
    engine_binary(B, path(Exe)),
    once(catch(absolute_file_name(path(Exe), _, [access(execute), file_errors(fail)]), _, fail)).

attest_engines :-
    findall(B, ( engine_binary(B, _), engine_available(B) ), Bs),
    (   Bs == []
    ->  format("no engine on PATH (scryer-prolog, tpl); nothing to attest~n")
    ;   forall(member(B, Bs), attest_engine(B))
    ).

attest_engine(B) :-
    attest_engine_report(B, Report),
    print_report(B, Report),
    \+ memberchk(_-impure(_), Report).

%!  attest_engine_report(+Backend, -Report) is det.
%
%   Report is a list of Indicator-Verdict: pure | impure(Fired) |
%   expected(Why, Fired) | not_defined | timeout | error(Text).
%   not_defined means the manifest names a predicate the engine, as
%   started, raised an existence error for: the manifest is stale.

attest_engine_report(B, Report) :-
    hornguard_profiles(_),
    findall(Ind, ( hornguard:hg_allow(_, Ind), hornguard:hg_engine(B, Ind) ), Inds0),
    sort(Inds0, Inds),
    attest_engine_report(B, Inds, Report).

%!  attest_engine_report(+Backend, +Indicators, -Report) is det.
%
%   The experiment on a chosen list of indicators, allowed or not. The
%   tests use it to check the wires fire on predicates known to be impure.

attest_engine_report(B, Inds, Report) :-
    maplist(indicator_shapes, Inds, Shapes),
    attest_engine_goals(B, Shapes, Report).

indicator_shapes(Ind, Ind-Goals) :-
    findall(I-G, ( shape(Ind, I, Args), Ind = N/_, G =.. [N|Args] ), Goals).

%!  attest_engine_goals(+Backend, +Probes, -Report) is det.
%
%   The experiment on chosen goals: Probes is a list of Id-Goal, or of
%   Id-[I-Goal, ...] for several shapes under one id, and Report pairs
%   each Id with its verdict. The tests use it with goals whose effects
%   are known, to check the wires fire.

attest_engine_goals(B, Probes, Report) :-
    engine_available(B),
    tmp_file(hg_engine_attest, Dir),
    make_directory(Dir),
    setup_call_cleanup(true,
                       once(( calibrate(B, Dir, Noise),
                              maplist(attest_one(B, Dir, Noise), Probes, Report0) )),
                       catch(delete_directory_and_contents(Dir), _, true)),
    Report = Report0,
    % Called from a module other than user, the body above is reported as
    % leaving a choicepoint; from user it is not. Every goal in it is
    % deterministic, so the cut costs nothing and the callers are det.
    !.

missing_marker(missing(_)).

%   What trips on `true` in this engine is the engine's own noise.
calibrate(B, Dir, Noise) :-
    run_probe(B, Dir, [1-true], Results),
    findall(W, ( member(shape(_, Ws), Results), member(W, Ws) ), Noise0),
    sort(Noise0, Noise).

attest_one(B, Dir, Noise, Id-Goals0, Id-Verdict) :-
    (   is_list(Goals0) -> Goals = Goals0 ; Goals = [1-Goals0] ),
    run_probe(B, Dir, Goals, Results),
    (   Results = timeout -> Verdict = timeout
    ;   Results = error(T) -> Verdict = error(T)
    ;   Id = N/A, forall(member(shape(_, Ws0), Results), memberchk(missing(N/A), Ws0))
    ->  Verdict = not_defined
    ;   findall(I-Ws, ( member(shape(I, Ws1), Results),
                        exclude(missing_marker, Ws1, Ws0),
                        subtract(Ws0, Noise, Ws), Ws \== [] ), Fired),
        (   Fired == [] -> Verdict = pure
        ;   expected(B, Id, Why) -> Verdict = expected(Why, Fired)
        ;   Verdict = impure(Fired)
        )
    ).

		 /*******************************
		 *           THE PROBE          *
		 *******************************/

%   Generate the probe for one list of I-Goal shapes, run it, read what it
%   wrote.
run_probe(B, Dir, Goals, Results) :-
    engine_binary(B, Exe),
    directory_file_path(Dir, 'hg_probe.pl', Probe),
    directory_file_path(Dir, 'hg_results', ResFile),
    directory_file_path(Dir, 'hg_out', OutFile),
    forall(member(F, [ResFile, OutFile]), catch(delete_file(F), _, true)),
    setup_call_cleanup(open(OutFile, write, S0), true, close(S0)),
    setup_call_cleanup(open(Probe, write, S), emit_probe(S, B, Goals), close(S)),
    process_timeout(T),
    process_create(Exe, [Probe], [stdout(null), stderr(null), process(Pid), cwd(Dir)]),
    bounded_wait(Pid, T, Status),
    (   Status == timeout
    ->  Results = timeout
    ;   exists_file(ResFile), read_results(ResFile, Results0), Results0 \== []
    ->  Results = Results0
    ;   Results = error(no_results)
    ).

%   Wait for the process, killing it at the deadline. The timeout option of
%   process_wait/3 is not honoured on every build (macOS, SWI 9.2.9: it
%   waits for exit regardless), so the bound is a watchdog thread that sends
%   SIGKILL — SIGTERM, which Trealla handles, leaves it running — and the
%   wait that follows is then finite. Status is timeout when the watchdog
%   fired, else the exit status.
bounded_wait(Pid, T, Status) :-
    mutex_create(M),
    thread_create(watchdog(Pid, T, M), Watchdog, []),
    catch(process_wait(Pid, S0), _, S0 = error),
    with_mutex(M, ( retract(watchdog_fired(Pid)) -> Fired = true ; Fired = false )),
    catch(thread_signal(Watchdog, throw(done)), _, true),
    thread_join(Watchdog, _),
    mutex_destroy(M),
    ( Fired == true -> Status = timeout ; Status = S0 ).

%   Shared between the waiting thread and the watchdog; global variables
%   are thread-local, a dynamic predicate is not.
:- dynamic watchdog_fired/1.

watchdog(Pid, T, M) :-
    catch(( sleep(T),
            with_mutex(M, ( catch(process_kill(Pid, kill), _, true),
                            assertz(watchdog_fired(Pid)) )) ),
          _, true).

read_results(File, Terms) :-
    catch(setup_call_cleanup(open(File, read, S), read_all(S, Terms), close(S)), _, Terms = []).

read_all(S, Terms) :-
    % Scryer's write_canonical spells a list '.'(H, T), which is not a list
    % to SWI 7 unless asked.
    catch(read_term(S, T, [dotlists(true)]), _, T = end_of_file),
    (   T == end_of_file -> Terms = []
    ;   Terms = [T|Rest], read_all(S, Rest)
    ).

%   Strict ISO plus what each engine needs to list a directory and bound a
%   call. Nothing is passed in: the shapes are facts in the file.
emit_probe(S, B, Goals) :-
    format(S, "%% GENERATED attestation probe inside ~w~n", [B]),
    engine_prelude(B, S),
    forall(between(1, 8, K),
           ( length(Ps, K), G =.. [hg_closure|Ps],
             write_term(S, G, [quoted(true), ignore_ops(true), numbervars(false)]),
             format(S, ".~n", []) )),
    forall(member(I-G, Goals),
           ( write_term(S, hg_shape(I, G), [quoted(true), ignore_ops(true), numbervars(false)]),
             format(S, ".~n", []) )),
    format(S, "~n", []),
    format(S, "hg_len([], 0).~nhg_len([_|T], N) :- hg_len(T, N0), N is N0 + 1.~n", []),
    format(S, "hg_dyn(L) :- findall(N/A-C, ( current_predicate(N/A), functor(H, N, A), catch(predicate_property(H, dynamic), _, fail), findall(x, catch(clause(H, _), _, fail), Cs), hg_len(Cs, C) ), L0), sort(L0, L).~n", []),
    engine_dir_arg(B, DirArg),
    format(S, "hg_files(L) :- ( catch(directory_files(~s, L0), _, fail) -> sort(L0, L) ; L = unavailable ).~n", [DirArg]),
    format(S, "hg_snap(snap(Fs, Os, Ss, Ps, Ds, Fi)) :- findall(F-V, current_prolog_flag(F, V), Fs0), sort(Fs0, Fs), findall(op(P, T, Nm), current_op(P, T, Nm), Os0), sort(Os0, Os), findall(St, stream_property(St, _), Ss0), sort(Ss0, Ss), findall(Nn/Aa, current_predicate(Nn/Aa), Ps0), sort(Ps0, Ps), hg_dyn(Ds), hg_files(Fi).~n", []),
    format(S, "hg_diff(snap(A1,B1,C1,D1,E1,F1), snap(A2,B2,C2,D2,E2,F2), Ws) :- hg_d(flags, A1, A2, W1), hg_d(ops, B1, B2, W2), hg_d(streams, C1, C2, W3), hg_d(preds, D1, D2, W4), hg_d(dynclauses, E1, E2, W5), hg_d(files, F1, F2, W6), hg_cat([W1,W2,W3,W4,W5,W6], Ws).~n", []),
    format(S, "hg_d(Name, X, Y, [Name]) :- X \\== Y, !.~nhg_d(_, _, _, []).~n", []),
    format(S, "hg_cat([], []).~nhg_cat([L|Ls], R) :- hg_cat(Ls, R0), hg_app(L, R0, R).~n", []),
    format(S, "hg_app([], L, L).~nhg_app([H|T], L, [H|R]) :- hg_app(T, L, R).~n", []),
    format(S, "hg_limited(G, Out) :- ( catch(hg_bounded(G), E, true) -> true ; true ), ( nonvar(E) -> Out = err(E) ; Out = ok ).~n", []),
    format(S, "hg_bounded(G) :- ( hg_has_limit -> call_with_inference_limit(once(G), 2000000, _) ; once(G) ).~n", []),
    format(S, "hg_has_limit :- catch(call_with_inference_limit(true, 10, _), _, fail).~n", []),
    format(S, "hg_out_nonempty :- open('hg_out', read, I), get_char(I, C), close(I), C \\== end_of_file.~n", []),
    format(S, "hg_run(R, I, G) :- hg_snap(S1), current_output(Old), open('hg_out', write, O), set_output(O), hg_limited(G, Out), set_output(Old), close(O), hg_snap(S2), hg_diff(S1, S2, Ws0), ( hg_out_nonempty -> Ws1 = [output|Ws0] ; Ws1 = Ws0 ), ( Out = err(error(existence_error(procedure, PI), _)) -> Ws = [missing(PI)|Ws1] ; Ws = Ws1 ), write_canonical(R, shape(I, Ws)), write(R, '.'), nl(R).~n", []),
    format(S, "hg_main :- open('hg_results', write, R), ( hg_shape(I, G), hg_run(R, I, G), fail ; true ), close(R), halt.~n", []),
    format(S, ":- initialization(hg_main).~n", []).

%   Only what the tripwires need. The manifest describes the engine as
%   started, and the candidates are what it defines then; a library loaded
%   here is part of the harness, calibrated out with the rest of the noise.
engine_prelude(scryer, S) :-
    format(S, ":- use_module(library(files)).~n:- use_module(library(iso_ext)).~n~n", []).
engine_prelude(trealla, _).

%   Scryer's directory_files/2 wants a chars list; Trealla's takes an atom.
engine_dir_arg(scryer, "\".\"").
engine_dir_arg(trealla, "'.'").

%   The same shapes the SWI harness uses, with the closures spelled as the
%   probe's own hg_closure/K predicates instead of lambdas.
data_value(a).
data_value(1).
data_value(2.5).
data_value([a, b]).
data_value(f(x)).
data_value(_).

%   The kinds of value known to make a quiet predicate act, in strict-ISO
%   spelling so every engine reads them the same. Swept one position at a
%   time with the other arguments neutral.
dangerous_value(user_error).
dangerous_value(user_output).
dangerous_value(user_input).
dangerous_value('hg_attest_probe.txt').
dangerous_value(double_quotes).
dangerous_value(unknown).
dangerous_value(700).
dangerous_value(xfx).
dangerous_value(hg_attest_op).
dangerous_value(user:true).
dangerous_value(write(x)).
dangerous_value([0'h, 0'g]).
dangerous_value([h, g]).
dangerous_value(-1).
dangerous_value(0).
dangerous_value(100000000000000000000).
dangerous_value('').
dangerous_value('$VAR'(1)).
dangerous_value(alias(hg_attest_alias)).
dangerous_value(end_of_file).
dangerous_value([]).
dangerous_value(true).

shape(true/0, 1, []) :- !.
shape(N/A, I, Args) :-
    modes(N/A, Modes),
    findall(V, data_value(V), Vs),
    (   nth1(I, Vs, V), maplist(mode_arg(V), Modes, Args)
    ;   I = 7, mixed_args(Modes, Args)
    ;   nth1(P, Modes, M), \+ goal_mode(M),
        findall(DV, dangerous_value(DV), DVs), nth1(K, DVs, DV),
        I = at(P, K),
        positional_args(Modes, P, DV, Args)
    ).

goal_mode(0).
goal_mode(^).
goal_mode(K) :- integer(K), K > 0.

positional_args([], _, _, []).
positional_args([M|Ms], P, V, [A|As]) :-
    (   P =:= 1 -> A = V ; mode_arg(a, M, A) ),
    P1 is P - 1,
    positional_args(Ms, P1, V, As).

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
mode_arg(_, K, C) :- integer(K), K > 0, !, closure(K, C).
mode_arg(V, _, A) :- ( var(V) -> true ; A = V ).      % a fresh variable per position

%   A closure completed with K arguments must resolve to hg_closure/K, so
%   the closure itself is hg_closure with none: hg_closure(X1..XK) exists.
closure(_, hg_closure).

mixed_args(Modes, Args) :-
    findall(V, data_value(V), Vs0), exclude(var, Vs0, Vs),
    mixed_args(Modes, Vs, 0, Args).

mixed_args([], _, _, []).
mixed_args([M|Ms], Vs, I, [A|As]) :-
    (   ( M == 0 ; M == (^) ) -> A = true
    ;   integer(M), M > 0 -> closure(M, A)
    ;   length(Vs, NV), J is I mod NV, nth0(J, Vs, A)
    ),
    I1 is I + 1,
    mixed_args(Ms, Vs, I1, As).

		 /*******************************
		 *            REPORT            *
		 *******************************/

print_report(B, Report) :-
    forall(member(Ind-V, Report), print_line(B, Ind, V)),
    aggregate_all(count, member(_-pure, Report), NPure),
    aggregate_all(count, member(_-impure(_), Report), NImp),
    aggregate_all(count, member(_-expected(_, _), Report), NExp),
    aggregate_all(count, member(_-timeout, Report), NTo),
    aggregate_all(count, member(_-not_defined, Report), NUd),
    aggregate_all(count, member(_-error(_), Report), NErr),
    format("~n~w: ~d pure, ~d expected, ~d impure, ~d timed out, ~d not defined, ~d probe errors~n",
           [B, NPure, NExp, NImp, NTo, NUd, NErr]).

print_line(_, _, pure) :- !.
print_line(B, Ind, timeout) :- !, format("timeout   ~w ~w~n", [B, Ind]).
print_line(B, Ind, not_defined) :- !, format("undefined ~w ~w  (manifest is stale)~n", [B, Ind]).
print_line(B, Ind, error(T)) :- !, format("error     ~w ~w  ~w~n", [B, Ind, T]).
print_line(B, Ind, expected(Why, Fired)) :- !,
    format("expected  ~w ~w  (~w)  ~q~n", [B, Ind, Why, Fired]).
print_line(B, Ind, impure(Fired)) :-
    format("IMPURE    ~w ~w  ~q~n", [B, Ind, Fired]).
