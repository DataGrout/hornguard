:- module(hornguard_worker,
          [ hornguard_worker_main/0,
            hornguard_read/4,          % +Backend, +Text, -Terms, -Report
            hornguard_read/5,          % +Backend, +Text, -Terms, -VarNames, -Report
            hornguard_canonical/2,     % +Term, -Text
            hornguard_canonical/3,     % +Term, +VarNames, -Text
            hornguard_judge_text/4     % +Op, +Text, +Options, -Response
          ]).

/** <module> Hornguard judge worker

The pack in its own process. A host of any language spawns

    swipl prolog/hornguard_worker_main.pl        (or: make worker)

and exchanges one JSON object per line over stdin/stdout. The worker reads
author text itself, under the backend's reader flags and with the standard
operator table, so the untrusted engine never parses author text: an
admitted term comes back in canonical form, and only that form should cross
to the engine. Reader-level hazards (syntax errors, quasi-quotations,
oversized input, more than one term where one is expected) are refused
under the `evasion` class with a `reader(Reason)` rule.

Handshake: on start the worker writes

    {"hello":"hornguard","protocol":1,"engine":"swi","version":"9.2.9",
     "profiles":[...]}

Requests carry an `id` (echoed), an `op`, and op-specific fields:

    {"id":1,"op":"judge_goal","text":"findall(X, member(X,[a]), L)",
     "backend":"swi","profiles":["iso","prologue"],
     "options":{"strict_negation":true,"defer_unknown":false,
                "allow":["foo/2"],"trust":[["bar/3","none"]]}}
    {"id":2,"op":"judge_clause","text":"p(X) :- q(X)."}
    {"id":3,"op":"judge_program","text":"p(1).\np(X) :- q(X)."}
    {"id":4,"op":"load_policy","path":"/etc/host/policy.pl"}
    {"id":5,"op":"load_profiles","dirs":["/a/profiles","/b/profiles"]}
    {"id":6,"op":"profiles"}
    {"id":7,"op":"ping"}

`backend`, `profiles` and `options` are optional; absent, the loaded policy
applies. Responses:

    {"id":1,"verdict":"admit","canonical":"findall(A,member(A,[a]),B)"}
    {"id":1,"verdict":"admit_needs","needs":[{"profile":"swi"}],"canonical":"..."}
    {"id":1,"verdict":"refused","class":"escape_attempt","rule":"pinned(process)",
     "depth":1,"reason":"permission_error(execute,goal,shell/1)"}
    {"id":4,"ok":true}
    {"id":9,"error":"unknown_op","detail":"..."}

The worker is sequential; hosts wanting parallelism run several.
*/

:- use_module(library(http/json)).
:- use_module(library(lists)).
:- use_module(library(apply)).
:- use_module(library(error)).
:- use_module(hornguard).

protocol_version(1).
max_input_bytes(1_000_000).

%   This module is also loaded as a library (tests, hosts that judge in
%   process), so it must not start the loop on load. hornguard_worker_main.pl
%   is the script that does.

hornguard_worker_main :-
    set_stream(user_output, encoding(utf8)),
    set_stream(user_input, encoding(utf8)),
    hello,
    loop.

hello :-
    protocol_version(P),
    current_prolog_flag(version_data, swi(Ma, Mi, Pa, _)),
    format(atom(V), "~w.~w.~w", [Ma, Mi, Pa]),
    catch(hornguard_profiles(Ps), _, Ps = []),
    reply(_{hello: hornguard, protocol: P, engine: swi, version: V, profiles: Ps}).

loop :-
    read_line_to_string(user_input, Line),
    (   Line == end_of_file
    ->  true
    ;   handle_line(Line),
        loop
    ).

handle_line(Line) :-
    (   catch(atom_json_dict(Line, Req, [value_string_as(string)]), _, fail),
        is_dict(Req)
    ->  catch(handle(Req, Resp), E, error_response(E, Resp))
    ;   Resp = _{id: null, error: bad_json, detail: "each request is one JSON object per line"}
    ),
    reply(Resp).

reply(Dict) :-
    with_output_to(string(S), json_write_dict(current_output, Dict, [width(0)])),
    format(user_output, "~s~n", [S]),
    flush_output(user_output).

error_response(E, _{error: internal, detail: D}) :-
    catch(message_to_string(E, D), _, term_string(D, E)).

handle(Req, Resp) :-
    (   get_dict(id, Req, Id) -> true ; Id = null ),
    (   get_dict(op, Req, Op0), string(Op0) -> atom_string(Op, Op0)
    ;   Op = missing
    ),
    dispatch(Op, Req, Resp0),
    put_dict(id, Resp0, Id, Resp).

dispatch(ping, _, _{ok: true}).
dispatch(profiles, _, _{ok: true, profiles: Ps}) :-
    hornguard_profiles(Ps).
dispatch(load_policy, Req, Resp) :-
    get_dict(path, Req, P0), string(P0), atom_string(P, P0),
    catch(( hornguard_load_policy(P), Resp = _{ok: true} ),
          E, ( message_to_string(E, D), Resp = _{error: policy, detail: D} )).
dispatch(load_profiles, Req, Resp) :-
    get_dict(dirs, Req, Ds0), is_list(Ds0), maplist([S, A]>>atom_string(A, S), Ds0, Ds),
    catch(( hornguard_load_profiles(Ds), Resp = _{ok: true} ),
          E, ( message_to_string(E, D), Resp = _{error: profiles, detail: D} )).
dispatch(Op, Req, Resp) :-
    memberchk(Op, [judge_goal, judge_clause, judge_program]), !,
    (   get_dict(text, Req, Text), string(Text)
    ->  request_options(Req, Backend, Options),
        hornguard_judge_text(Op, Text, [backend(Backend)|Options], Resp)
    ;   Resp = _{error: bad_request, detail: "text (string) is required"}
    ).
dispatch(Op, _, _{error: unknown_op, detail: D}) :-
    format(string(D), "unknown op ~w", [Op]).

%   Per-request overrides over the loaded policy.
request_options(Req, Backend, Options) :-
    hornguard_policy(policy(PB, PPs, POpts, PAllow, PTrust)),
    (   get_dict(backend, Req, B0), string(B0) -> atom_string(Backend, B0) ; Backend = PB ),
    (   get_dict(profiles, Req, Ps0), is_list(Ps0) -> maplist([S, A]>>atom_string(A, S), Ps0, Ps) ; Ps = PPs ),
    (   get_dict(options, Req, O), is_dict(O) -> true ; O = _{} ),
    (   get_dict(strict_negation, O, SN), hg_bool(SN) -> Opts1 = [strict_negation(SN)] ; opt_from_policy(strict_negation, POpts, Opts1) ),
    (   get_dict(defer_unknown, O, DU), hg_bool(DU) -> Opts2 = [defer_unknown(DU)] ; opt_from_policy(defer_unknown, POpts, Opts2) ),
    (   get_dict(allow, O, Al0), is_list(Al0) -> maplist(indicator_from_json, Al0, Al) ; Al = PAllow ),
    (   get_dict(trust, O, Tr0), is_list(Tr0) -> maplist(trust_from_json, Tr0, Tr) ; Tr = PTrust ),
    append([[profiles(Ps), allow(Al), trust(Tr)], Opts1, Opts2], Options).

hg_bool(true). hg_bool(false).

opt_from_policy(Name, POpts, [Opt]) :- functor(Opt, Name, 1), memberchk(Opt, POpts), !.
opt_from_policy(_, _, []).

indicator_from_json(S, N/A) :-
    string(S), term_string(T, S), T = N/A, atom(N), integer(A), !.
indicator_from_json(S, _) :-
    throw(error(domain_error(indicator, S), _)).

trust_from_json([IS, SpecS], Ind-Spec) :-
    indicator_from_json(IS, Ind),
    ( SpecS == "none" -> Spec = none ; term_string(Spec, SpecS) ), !.
trust_from_json(X, _) :-
    throw(error(domain_error(trust_entry, X), _)).


		 /*******************************
		 *         READ + JUDGE         *
		 *******************************/

%!  hornguard_judge_text(+Op, +Text, +Options, -Response) is det.
%
%   Op is judge_goal | judge_clause | judge_program. Options carry
%   backend(B), profiles(Ps) and the judge options. Response is a dict
%   with the verdict fields described in the module header.

hornguard_judge_text(Op, Text, Options, Resp) :-
    memberchk(backend(Backend), Options),
    memberchk(profiles(Profiles), Options),
    exclude([O]>>( O = backend(_) ; O = profiles(_) ), Options, JudgeOpts),
    terminate_text(Op, Text, Text1),
    hornguard_read(Backend, Text1, Terms, VarNames, Report),
    (   Report == ok
    ->  arity_check(Op, Terms, VarNames, Resp0),
        (   Resp0 = ok(Term, Names)
        ->  judge(Op, Backend, Profiles, Term, JudgeOpts, Verdict),
            verdict_response(Verdict, Term, Names, Resp)
        ;   Resp = Resp0
        )
    ;   Report = refused(Reason),
        term_string(Reason, RS),
        Resp = _{verdict: refused, class: evasion, rule: RS, reason: RS}
    ).

%   A single goal or clause is usually sent without its terminating period;
%   supply one. A program is a sequence of terminated clauses and is read
%   as given.
terminate_text(judge_program, Text, Text) :- !.
terminate_text(_, Text0, Text) :-
    normalize_space(string(T), Text0),
    (   sub_string(T, _, 1, 0, ".") -> Text = T
    ;   string_concat(T, " .", Text)
    ).

arity_check(judge_program, Terms, Names, ok(Terms, Names)) :- !.
arity_check(_, [Term], [Names], ok(Term, Names)) :- !.
arity_check(_, Terms, _, _{verdict: refused, class: evasion, rule: "reader(term_count)", reason: R}) :-
    length(Terms, N),
    format(string(R), "expected one term, read ~d", [N]).

judge(judge_goal, B, Ps, T, O, V) :- hornguard_admit(B, Ps, T, O, V).
judge(judge_clause, B, Ps, T, O, V) :- hornguard_admit_clause(B, Ps, T, O, V).
judge(judge_program, B, Ps, T, O, V) :- hornguard_admit_program(B, Ps, T, O, V).

verdict_response(admit, Term, Names, _{verdict: admit, canonical: C}) :-
    canonical_of(Term, Names, C).
verdict_response(admit_needs(Needs), Term, Names, _{verdict: admit_needs, needs: Ns, canonical: C}) :-
    maplist(need_json, Needs, Ns),
    canonical_of(Term, Names, C).
verdict_response(refused(Reason, Class, Rule0), _, _, Resp) :-
    (   Rule0 = Rule + depth(D) -> true ; Rule = Rule0, D = 0 ),
    term_string(Reason, RS), term_string(Rule, RuS),
    Resp = _{verdict: refused, class: Class, rule: RuS, depth: D, reason: RS}.

need_json(profile(P), _{profile: P}).
need_json(predicate(N/A), _{predicate: S}) :- format(string(S), "~w/~w", [N, A]).

canonical_of(Terms, NamesList, C) :-
    is_list(Terms), !,
    maplist(hornguard_canonical, Terms, NamesList, Cs),
    atomic_list_concat(Cs, '\n', C0), atom_string(C0, C).
canonical_of(Term, Names, C) :-
    hornguard_canonical(Term, Names, C).


		 /*******************************
		 *            READER            *
		 *******************************/

%!  hornguard_read(+Backend, +Text, -Terms, -Report) is det.
%!  hornguard_read(+Backend, +Text, -Terms, -VarNames, -Report) is det.
%
%   Read author text under the backend's reader flags, with the standard
%   operator table (this module defines no operators), refusing
%   quasi-quotations and oversized input. Report is `ok` or
%   `refused(reader(Why))`. VarNames has one `Name=Var` list per term, so
%   the canonical form can keep the author's variable names and a host can
%   map bindings back.

hornguard_read(Backend, Text, Terms, Report) :-
    hornguard_read(Backend, Text, Terms, _, Report).

hornguard_read(Backend, Text, Terms, VarNames, Report) :-
    string_length(Text, Len),
    max_input_bytes(Max),
    (   Len > Max
    ->  Terms = [], VarNames = [], Report = refused(reader(too_large))
    ;   backend_double_quotes(Backend, DQ),
        catch(read_all_terms(Text, DQ, Terms, VarNames, Report),
              E, reader_error(E, Terms, VarNames, Report))
    ).

backend_double_quotes(swi, string) :- !.
backend_double_quotes(scryer, chars) :- !.
backend_double_quotes(trealla, chars) :- !.
backend_double_quotes(_, codes).

read_all_terms(Text, DQ, Terms, VarNames, Report) :-
    setup_call_cleanup(
        open_string(Text, S),
        read_terms(S, DQ, Terms, VarNames, Report),
        close(S)).

read_terms(S, DQ, Terms, VarNames, Report) :-
    read_term(S, T, [ syntax_errors(error), module(hornguard_worker),
                      double_quotes(DQ), quasi_quotations(QQ0),
                      variable_names(VN) ]),
    ( var(QQ0) -> QQ = [] ; QQ = QQ0 ),
    (   T == end_of_file
    ->  Terms = [], VarNames = [], Report = ok
    ;   QQ \== []
    ->  Terms = [], VarNames = [], Report = refused(reader(quasi_quotation))
    ;   read_terms(S, DQ, Rest, RestNames, Report0),
        (   Report0 == ok -> Terms = [T|Rest], VarNames = [VN|RestNames], Report = ok
        ;   Terms = [], VarNames = [], Report = Report0
        )
    ).

reader_error(error(syntax_error(What), _), [], [], refused(reader(syntax_error(What)))) :- !.
reader_error(error(resource_error(What), _), [], [], refused(reader(resource(What)))) :- !.
reader_error(E, [], [], refused(reader(E))).


		 /*******************************
		 *          CANONICAL           *
		 *******************************/

%!  hornguard_canonical(+Term, -Text) is det.
%!  hornguard_canonical(+Term, +VarNames, -Text) is det.
%
%   Operator-free canonical text: every compound in functional notation,
%   atoms quoted where needed. With VarNames (`Name=Var` pairs from the
%   reader) the author's variable names are kept, so a host can map the
%   engine's bindings back to them; every other variable is anonymous and
%   prints as `_`. Without names, variables are lettered in order of
%   appearance and singletons print as `_`. Only this form should cross to
%   the engine.

hornguard_canonical(Term0, Text) :-
    copy_term(Term0, Term),
    numbervars(Term, 0, _, [singletons(true)]),
    canonical_write(Term, Text).

hornguard_canonical(Term0, VarNames0, Text) :-
    copy_term(Term0-VarNames0, Term-VarNames),
    maplist(name_var, VarNames),
    term_variables(Term, Anon),
    maplist([V]>>(V = '$VAR'('_')), Anon),
    canonical_write(Term, Text).

name_var(Name=V) :- ( var(V) -> V = '$VAR'(Name) ; true ).

canonical_write(Term, Text) :-
    with_output_to(string(Text),
                   write_term(Term, [ quoted(true), ignore_ops(true),
                                      numbervars(true), spacing(standard) ])).
