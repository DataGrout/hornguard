:- module(test_worker, []).

%% The judge worker: reader, canonical form, and the stdio protocol.
%% Reader fixtures run in-process against hornguard_read/4 and
%% hornguard_canonical/2; the protocol tests spawn the real worker.

:- use_module(library(plunit)).
:- use_module(library(lists)).
:- use_module(library(process)).
:- use_module(library(readutil)).
:- use_module(library(http/json)).
:- use_module('../prolog/hornguard').
:- use_module('../prolog/hornguard_worker').

:- dynamic rfix/4.
:- dynamic here/1.
:- prolog_load_context(directory, D), retractall(here(_)), assertz(here(D)).

load_reader_fixtures :-
    retractall(rfix(_, _, _, _)),
    here(D), atomic_list_concat([D, '/../fixtures/reader'], Dir0), absolute_file_name(Dir0, Dir),
    directory_files(Dir, Fs),
    forall(( member(F, Fs), file_name_extension(_, pl, F) ),
           ( directory_file_path(Dir, F, P),
             setup_call_cleanup(open(P, read, In), read_rfix(In), close(In)) )).

read_rfix(In) :-
    read_term(In, T, []),
    (   T == end_of_file -> true
    ;   ( T = reader(Id, B, Text, Exp) -> assertz(rfix(Id, B, Text, Exp)) ; true ),
        read_rfix(In)
    ).

:- initialization(load_reader_fixtures).

canonical_via_worker(Backend, Text, Result) :-
    hornguard_judge_text(judge_goal, Text, [backend(Backend), profiles([])], R),
    (   get_dict(canonical, R, C) -> Result = C
    ;   get_dict(class, R, evasion), get_dict(rule, R, RuleS) -> term_string(Rule, RuleS), Result = refused(Rule)
    ;   Result = other(R)
    ).

:- begin_tests(reader).

terminated(Text, TT) :-
    normalize_space(string(T), Text),
    ( sub_string(T, _, 1, 0, ".") -> TT = T ; string_concat(T, " .", TT) ).

test(reader_fixture, [ forall(rfix(Id, B, Text, Exp)), true(Ok == yes) ]) :-
    % Only the reader and canonical form are under test here.
    terminated(Text, TT),
    hornguard_read(B, TT, Terms, Names, Report),
    (   Exp = refused(reader(_))
    ->  (   ( Report = refused(Rule), Exp = refused(Rule) ) -> Ok = yes
        ;   ( Report == ok, Terms = [_, _|_], Exp == refused(reader(term_count)) ) -> Ok = yes
        ;   Ok = got(Report, Terms)
        )
    ;   (   Report == ok, Terms = [T], Names = [VN], hornguard_canonical(T, VN, C), C == Exp -> Ok = yes
        ;   Report == ok, Terms = [T], Names = [VN] -> hornguard_canonical(T, VN, C), Ok = mismatch(Id, C)
        ;   Ok = got(Report)
        )
    ).

test(canonical_is_a_fixed_point, [ forall(( rfix(_, B, Text, Exp), string(Exp) )), true(C2 == Exp) ]) :-
    terminated(Text, TT),
    hornguard_read(B, TT, [T], [VN], ok),
    hornguard_canonical(T, VN, C1),
    terminated(C1, C1T),
    hornguard_read(B, C1T, [T2], [VN2], ok),
    hornguard_canonical(T2, VN2, C2).

test(engine_reader_agrees_on_swi, [ forall(( rfix(_, swi, Text, Exp), string(Exp) )), true(C == Exp) ]) :-
    % The backend engine's own reader on the same text, canonicalised, must
    % match: the reader-agreement check for the swi backend.
    terminated(Text, TT),
    term_string(T, TT, [double_quotes(string), variable_names(VN)]),
    hornguard_canonical(T, VN, C).

%   Cross-engine agreement. The canonical form only earns its place if the
%   target engine reads it into the term we meant: if it does not, handing
%   the engine canonical text instead of the author's is a bug rather than a
%   defence. Skipped when the engine is not installed.

engine_binary(scryer, path('scryer-prolog')).
engine_binary(trealla, path(tpl)).

%   Checked inside the generator rather than as a plunit condition: a
%   condition is evaluated once, before forall binds the backend, so it would
%   pass for whichever engine happened to come first and then run the rest
%   against an engine that is not there.
engine_available(Backend) :-
    engine_binary(Backend, path(Exe)),
    catch(absolute_file_name(path(Exe), _, [access(execute), file_errors(fail)]), _, fail).

%   Ask Engine to read the canonical text and write back what it read, in
%   its own canonical form; read that here and compare terms up to variable
%   renaming. Comparing terms rather than strings keeps engine-specific
%   spacing and quoting out of the answer.
%
%   The text goes through a file rather than into the script, because
%   embedding it would need per-engine quoting of exactly the characters
%   under test. The script itself is then pure ISO and identical for every
%   engine.
engine_round_trip(Backend, Text, Term) :-
    engine_binary(Backend, path(Exe)),
    tmp_file(hg_in, In), tmp_file(hg_out, Out),
    setup_call_cleanup(open(In, write, S0), format(S0, "~s .~n", [Text]), close(S0)),
    tmp_file_stream(text, Script, S1),
    format(S1, "main :- open(~q, read, I), read_term(I, T, []), close(I),~n", [In]),
    format(S1, "        open(~q, write, O), write_canonical(O, T), write(O, '.'), nl(O),~n", [Out]),
    format(S1, "        close(O), halt.~n:- initialization(main).~n", []),
    close(S1),
    process_create(path(Exe), [Script], [stdout(null), stderr(null), process(Pid)]),
    process_wait(Pid, _),
    catch(read_file_to_terms(Out, [Raw], []), _, fail),
    iso_lists(Raw, Term),
    forall(member(F, [In, Out, Script]), catch(delete_file(F), _, true)).

%   SWI's list constructor is '[|]'; ISO's, and therefore Scryer's and
%   Trealla's, is '.'. So an engine's write_canonical emits `'.'(a,[])` where
%   SWI would emit `[a]`, and SWI reads that back as an ordinary compound
%   rather than a list. That is a property of moving a term between the two
%   writers, not a disagreement about what the engine read: the canonical
%   form we send uses list notation, which every engine here reads correctly.
%   Normalise it away so the comparison is about the term.
%   Matched structurally rather than by pattern: '.'(H,T) written in SWI
%   source is dict notation, not a compound.
iso_lists(V, V) :- var(V), !.
iso_lists(T, T) :- atomic(T), !.
iso_lists(T0, T) :-
    compound_name_arity(T0, '.', 2), !,
    arg(1, T0, H0), arg(2, T0, Tl0),
    iso_lists(H0, H), iso_lists(Tl0, Tl),
    T = [H|Tl].
iso_lists(T0, T) :-
    T0 =.. [F|As0],
    maplist(iso_lists, As0, As),
    T =.. [F|As].

test(engine_reads_our_canonical_form_as_the_same_term,
     [ forall(( rfix(_, B, _Text, Exp), string(Exp), memberchk(B, [scryer, trealla]),
                engine_available(B) )),
       true(Same == true) ]) :-
    terminated(Exp, ExpT),
    hornguard_read(B, ExpT, [Ours], _, ok),
    (   engine_round_trip(B, Exp, Theirs)
    ->  ( Ours =@= Theirs -> Same = true ; Same = Ours-Theirs )
    ;   Same = could_not_run_engine
    ).

test(oversized_input_refused, [true(R == refused(reader(too_large)))]) :-
    length(L, 1_000_100), maplist(=(0'a), L), string_codes(S, L),
    hornguard_read(swi, S, _, R).

test(programmatic_canonical_keeps_author_dollar_var_terms_as_data,
     [true(C == "f('$VAR'('Shell'),'$VAR'(3),A,A,_)")]) :-
    hornguard_canonical(f('$VAR'('Shell'), '$VAR'(3), X, X, _Y), C).

test(named_canonical_keeps_author_dollar_var_terms_as_data,
     [true(C == "f('$VAR'('Shell'),X,_)")]) :-
    hornguard_canonical(f('$VAR'('Shell'), X, _Y), ['X'=X], C).

test(programmatic_canonical_letters_and_underscores_singletons, [true(C == "findall(A,member(A,[a]),_)")]) :-
    hornguard_canonical(findall(X, member(X, [a]), _L), C).

:- end_tests(reader).


		 /*******************************
		 *           PROTOCOL           *
		 *******************************/

worker_path(P) :-
    here(D), atomic_list_concat([D, '/../prolog/hornguard_worker_main.pl'], P0), absolute_file_name(P0, P).

%   with_worker(-In, -Out, :Goal): spawn the worker, bind its pipes, run Goal.
%   Plain call, no lambda: bindings made by Goal stay visible to the test.
with_worker(In, Out, Goal) :-
    worker_path(W),
    setup_call_cleanup(
        process_create(path(swipl), ['-q', W], [stdin(pipe(In)), stdout(pipe(Out)), process(Pid)]),
        ( set_stream(In, encoding(utf8)), set_stream(Out, encoding(utf8)),
          call(Goal) ),
        ( close(In), catch(read_rest(Out), _, true), close(Out), process_wait(Pid, _) )).

read_rest(Out) :- read_line_to_string(Out, L), ( L == end_of_file -> true ; read_rest(Out) ).

send(In, Dict) :-
    with_output_to(string(S), json_write_dict(current_output, Dict, [width(0)])),
    format(In, "~s~n", [S]), flush_output(In).

recv(Out, Dict) :-
    read_line_to_string(Out, L),
    L \== end_of_file,
    atom_json_dict(L, Dict, [value_string_as(string)]).

roundtrip(In, Out, Req, Resp) :- send(In, Req), recv(Out, Resp).

:- begin_tests(protocol).

test(handshake, [true(( Hello == "hornguard", Proto == 1, IsList == true ))]) :-
    with_worker(_In, Out, recv(Out, H)),
    get_dict(hello, H, Hello), get_dict(protocol, H, Proto),
    ( get_dict(profiles, H, Ps), is_list(Ps) -> IsList = true ; IsList = false ).

test(ping_echoes_id, [true(( Ok == true, Id == 7 ))]) :-
    with_worker(In, Out, ( recv(Out, _), roundtrip(In, Out, _{id: 7, op: ping}, R) )),
    get_dict(ok, R, Ok), get_dict(id, R, Id).

test(admit_with_canonical, [true(( V == "admit", C == "findall(X,member(X,[a,b]),L)" ))]) :-
    with_worker(In, Out, ( recv(Out, _),
        roundtrip(In, Out, _{id: 1, op: judge_goal, text: "findall(X, member(X,[a,b]), L)", profiles: [iso, prologue]}, R) )),
    get_dict(verdict, R, V), get_dict(canonical, R, C).

test(refused_carries_class_rule_depth, [true(( V == "refused", Cl == "escape_attempt", Ru == "pinned(flags_ops)", D == 1 ))]) :-
    with_worker(In, Out, ( recv(Out, _),
        roundtrip(In, Out, _{id: 2, op: judge_goal, text: "findall(H, current_prolog_flag(home, H), _)", profiles: [iso, prologue]}, R) )),
    get_dict(verdict, R, V), get_dict(class, R, Cl), get_dict(rule, R, Ru), get_dict(depth, R, D).

test(needs_are_structured, [true(( V == "admit_needs", P == "swi" ))]) :-
    with_worker(In, Out, ( recv(Out, _),
        roundtrip(In, Out, _{id: 3, op: judge_goal, text: "string_concat(a, b, C)", profiles: [iso]}, R) )),
    get_dict(verdict, R, V), get_dict(needs, R, [N]), get_dict(profile, N, P).

test(clause_and_program_ops, [true(( CV == "admit_needs", PV == "refused", PC == "semantics" ))]) :-
    with_worker(In, Out, ( recv(Out, _),
        roundtrip(In, Out, _{id: 4, op: judge_clause, text: "p(X) :- q(X)", profiles: [iso], options: _{defer_unknown: true}}, C),
        roundtrip(In, Out, _{id: 5, op: judge_program, text: "p(1).\np(X) :- q(X), \\+ p(X).\nq(1).", profiles: [iso]}, P) )),
    get_dict(verdict, C, CV), get_dict(verdict, P, PV), get_dict(class, P, PC).

test(reader_refusals_are_evasion, [true(( SC == "evasion", QC == "evasion", TR == "reader(term_count)" ))]) :-
    with_worker(In, Out, ( recv(Out, _),
        roundtrip(In, Out, _{id: 6, op: judge_goal, text: "foo(", profiles: [iso]}, S),
        roundtrip(In, Out, _{id: 7, op: judge_goal, text: "X = {|html||<b>|}", profiles: [iso]}, Q),
        roundtrip(In, Out, _{id: 8, op: judge_goal, text: "a. b.", profiles: [iso]}, T) )),
    get_dict(class, S, SC), get_dict(class, Q, QC), get_dict(rule, T, TR).

test(per_request_trust_and_options, [true(( V == "refused", Ru == "pinned(process)", D == 1 ))]) :-
    with_worker(In, Out, ( recv(Out, _),
        roundtrip(In, Out, _{id: 9, op: judge_goal, text: "with_tenant(t, halt)", profiles: [iso],
                             options: _{trust: [["with_tenant/2", "with_tenant(?,0)"]]}}, R) )),
    get_dict(verdict, R, V), get_dict(rule, R, Ru), get_dict(depth, R, D).

test(bad_requests_do_not_kill_the_worker, [true(( BE == "bad_json", UE == "unknown_op", ME == "bad_request", POk == true ))]) :-
    with_worker(In, Out, ( recv(Out, _),
        format(In, "not json at all~n", []), flush_output(In), recv(Out, B),
        roundtrip(In, Out, _{id: 10, op: bogus}, U),
        roundtrip(In, Out, _{id: 11, op: judge_goal}, M),
        roundtrip(In, Out, _{id: 12, op: ping}, P) )),
    get_dict(error, B, BE), get_dict(error, U, UE), get_dict(error, M, ME), get_dict(ok, P, POk).

test(policy_load_over_protocol, [true(( LOk == true, RV == "admit" ))]) :-
    here(D), atomic_list_concat([D, '/policies/host.pl'], P0), absolute_file_name(P0, Policy), atom_string(Policy, PS),
    with_worker(In, Out, ( recv(Out, _),
        roundtrip(In, Out, _{id: 13, op: load_policy, path: PS}, L),
        roundtrip(In, Out, _{id: 14, op: judge_goal, text: "customer_tier(C, gold), lookup_price(C, _, _)"}, R) )),
    get_dict(ok, L, LOk), get_dict(verdict, R, RV).

:- end_tests(protocol).
