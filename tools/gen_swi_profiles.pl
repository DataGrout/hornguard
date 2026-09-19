:- module(hornguard_gen_swi_profiles, [ gen_swi_profiles/0, gen_swi_profiles/1 ]).

%% Generate profiles/swi.pl: the SWI-Prolog engine profiles.
%%
%% Candidates are the predicates that (a) the engine defines in `system` or
%% in one of the listed libraries, (b) SWI's library(sandbox) declares safe
%% when their goal arguments are instantiated, and (c) Hornguard does not
%% already know from `iso` or `prologue`. From those, everything matching a
%% pinned class is dropped (the pins are deliberate and stricter than
%% sandbox), everything in the exclusion table below is dropped with its
%% reason, and the rest is emitted grouped by source module as one profile
%% per module (`swi` for system, `swi_lists` for library(lists), ...).
%% Meta specs are derived from the engine's meta_predicate declarations.
%%
%% The output is a starting point for attestation, not an attestation. The
%% file header records the engine version and date; a reviewer signs it by
%% editing the header.
%%
%% Run: swipl -g gen_swi_profiles -t halt tools/gen_swi_profiles.pl

:- use_module(library(lists)).
:- use_module(library(apply)).
:- use_module(library(sandbox)).
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
:- use_module(library(random)).
:- use_module(library(backcomp)).
:- use_module('../prolog/hornguard').

source_profile(system,             swi).
source_profile(dif,                swi).
source_profile(lists,              swi_lists).
source_profile(apply,              swi_apply).
source_profile(aggregate,          swi_aggregate).
source_profile(solution_sequences, swi_solution_sequences).
source_profile(strings,            swi_strings).
source_profile(pairs,              swi_pairs).
source_profile(ordsets,            swi_ordsets).
source_profile(assoc,              swi_assoc).
source_profile(occurs,             swi_terms).
source_profile(terms,              swi_terms).
source_profile(error,              swi_error).
source_profile(random,             swi_random).
source_profile(backward_compatibility, swi_backcomp).

%   exclude(Indicator, Reason). Sandbox-safe predicates that stay out.
exclude('<meta-call>'/1,           internal).
exclude(abort/0,                   process).
exclude(at_halt/1,                 process).
exclude(cancel_halt/1,             process).
exclude(sleep/1,                   timing).
exclude(statistics/2,              reflection).
exclude(thread_self/1,             threads).
exclude(get_time/1,                timing).
exclude(format_time/3,             timing).
exclude(format_time/4,             timing).
exclude(stamp_date_time/3,         timing).
exclude(date_time_stamp/2,         timing).
exclude(compiling/0,               reflection).
exclude(gc_file_search_cache/1,    filesystem).
exclude(trie_gen_compiled/2,       internal).
exclude(trie_gen_compiled/3,       internal).
exclude(term_expansion/4,          loading).
exclude(undefined/0,               wfs_opt_in).
exclude(answer_count_restraint/0,  wfs_opt_in).
exclude(radial_restraint/0,        wfs_opt_in).
exclude(import_module/2,           reflection).
exclude(default_module/2,          reflection).
exclude(strip_module/3,            reflection).
exclude(current_type/3,            reflection).
exclude(current_arithmetic_function/1, reflection).
exclude(predicate_option_mode/2,   reflection).
exclude(predicate_option_type/2,   reflection).
exclude(is_stream/1,               streams).
exclude(blob/2,                    reflection).
exclude(attvar/1,                  attributes_deferred).
exclude(get_attr/3,                attributes_deferred).
exclude(get_attrs/2,               attributes_deferred).
exclude(del_attr/2,                destructive_state).
exclude(del_attrs/1,               destructive_state).
exclude(term_attvars/2,            attributes_deferred).
exclude(copy_term/4,               attributes_deferred).
exclude((/)/2,                     lambdas_deferred).
exclude((/)/3,                     lambdas_deferred).
exclude((/)/4,                     lambdas_deferred).
exclude((/)/9,                     lambdas_deferred).
exclude(is_lambda/1,               lambdas_deferred).
exclude(lambda_calls/2,            lambdas_deferred).
exclude(lambda_calls/3,            lambdas_deferred).
exclude(file_base_name/2,          filesystem).
exclude(file_directory_name/2,     filesystem).
exclude(file_name_extension/3,     filesystem).
exclude(b_set_dict/3,              destructive_state).
exclude(nb_set_dict/3,             destructive_state).
exclude(nb_link_dict/3,            destructive_state).
exclude(nb_linkarg/3,              destructive_state).
exclude(dict_create/3,             dicts_deferred).
exclude(dict_pairs/3,              dicts_deferred).
exclude(del_dict/4,                dicts_deferred).
exclude(get_dict/3,                dicts_deferred).
exclude(get_dict/5,                dicts_deferred).
exclude(put_dict/3,                dicts_deferred).
exclude(put_dict/4,                dicts_deferred).
exclude(select_dict/3,             dicts_deferred).
exclude(is_dict/1,                 dicts_deferred).
exclude(is_dict/2,                 dicts_deferred).
exclude((:<)/2,                    dicts_deferred).
exclude((>:<)/2,                   dicts_deferred).
exclude(phrase/2,                  dcg_deferred).
exclude(phrase/3,                  dcg_deferred).

gen_swi_profiles :-
    gen_swi_profiles('profiles/swi.pl').

gen_swi_profiles(Out) :-
    % The previous output is itself a profile file; judging with it loaded
    % would either bias the candidates or, after a new pin, fail the policy
    % check. Regeneration starts from iso, prologue and pinned only.
    ( exists_file(Out) -> delete_file(Out) ; true ),
    findall(M-Ind, candidate(M, Ind), Cands0),
    sort(Cands0, Cands),
    partition_candidates(Cands, Kept, Dropped),
    setup_call_cleanup(open(Out, write, S),
                       emit(S, Kept, Dropped),
                       close(S)),
    length(Kept, NK), length(Dropped, ND),
    format("wrote ~w: ~d allowed, ~d dropped~n", [Out, NK, ND]).

candidate(M, N/A) :-
    ( M = system ; source_profile(M, _), M \== system ),
    current_predicate(M:N/A),
    \+ sub_atom(N, 0, _, _, '$'),
    functor(H, N, A),
    predicate_property(M:H, defined),
    \+ predicate_property(M:H, imported_from(_)),
    ( M == system -> true ; predicate_property(M:H, exported) ),
    sandbox_safe(M:H),
    % Not covered by the hand-written profiles. Checked directly rather than
    % through the judge so that a previously generated swi.pl, if loaded,
    % cannot hide its own entries from regeneration.
    hornguard_profiles(_),
    \+ hornguard:hg_allow(iso, N/A),
    \+ hornguard:hg_allow(prologue, N/A).

sandbox_safe(M:G0) :-
    instantiate(M:G0, G),
    catch(sandbox:safe_goal(M:G), _, fail).

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
fill_arg(K, _, true) :- integer(K), K > 2, !.
fill_arg(_, A, A).

partition_candidates([], [], []).
partition_candidates([M-Ind|T], Kept, Dropped) :-
    (   exclude(Ind, Why)
    ->  Dropped = [Ind-Why|D1], Kept = K1
    ;   hornguard:hg_pinned(Class, Ind)
    ->  Dropped = [Ind-pinned(Class)|D1], Kept = K1
    ;   Kept = [M-Ind|K1], Dropped = D1
    ),
    partition_candidates(T, K1, D1).

emit(S, Kept, Dropped) :-
    current_prolog_flag(version_data, swi(Ma, Mi, Pa, _)),
    format(atom(V), "~w.~w.~w", [Ma, Mi, Pa]),
    get_time(Now), format_time(atom(Date), '%Y-%m-%d', Now),
    format(S, "%% Profiles `swi*`: SWI-Prolog engine predicates beyond `iso` and `prologue`.~n", []),
    format(S, "%%~n%% GENERATED by tools/gen_swi_profiles.pl on ~w against SWI-Prolog ~w.~n", [Date, V]),
    format(S, "%% Source: predicates the engine defines that library(sandbox) declares safe~n", []),
    format(S, "%% and that iso/prologue do not cover, minus pinned classes and the tool's~n", []),
    format(S, "%% exclusion table. This is a starting point for attestation, not an~n", []),
    format(S, "%% attestation. Reviewed by: (pending)~n%%~n", []),
    format(S, "%% Dropped (sandbox-safe, kept out, with reason):~n", []),
    forall(member(Ind-Why, Dropped), format(S, "%%   ~q~t~40|~w~n", [Ind, Why])),
    format(S, "~n:- multifile allow/2, meta_spec/2.~n", []),
    forall(( source_profile(M, P), once(member(M-_, Kept)) ),
           emit_profile(S, M, P, Kept)).

emit_profile(S, M, P, Kept) :-
    format(S, "~n%% ~w (from ~w)~n", [P, M]),
    forall(member(M-Ind, Kept), format(S, "allow(~w, ~q).~n", [P, Ind])),
    forall(( member(M-Ind, Kept), meta_spec_for(M, Ind, Spec) ),
           format(S, "meta_spec(~w, ~q).~n", [P, Spec])).

meta_spec_for(M, N/A, Spec) :-
    functor(H, N, A),
    catch(predicate_property(M:H, meta_predicate(Spec0)), _, fail),
    Spec0 =.. [N|Modes0],
    maplist(normalize_mode, Modes0, Modes),
    member(GoalMode, Modes), goal_mode(GoalMode), !,
    Spec =.. [N|Modes].

normalize_mode(0, 0) :- !.
normalize_mode(^, ^) :- !.
normalize_mode(K, K) :- integer(K), K > 0, !.
normalize_mode(_, ?).

goal_mode(0).
goal_mode(^).
goal_mode(K) :- integer(K), K > 0.
