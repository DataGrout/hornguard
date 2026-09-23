%% Pinned capability classes. A predicate in a pinned class is refused
%% regardless of profile, and an allow/2 naming one is a policy load error.
%% Reopening a class requires an explicit unpin directive, logged as a warning
%% at load.
%%
%% Indicators are the union across backends; a backend's manifest says which
%% exist for it. Name-only entries (Name/_) pin every arity: that is deliberate
%% here and only here, because a single unpinned arity of `open` or `format`
%% is the whole game.

pinned(database, assert/_).
pinned(database, asserta/_).
pinned(database, assertz/_).
pinned(database, retract/_).
pinned(database, retractall/_).
pinned(database, abolish/_).
pinned(database, (dynamic)/_).

pinned(streams, open/_).
pinned(streams, close/_).
pinned(streams, read/_).
pinned(streams, read_term/_).
pinned(streams, write/_).
pinned(streams, writeq/_).
pinned(streams, write_canonical/_).
pinned(streams, write_term/_).
pinned(streams, print/_).
pinned(streams, nl/_).
pinned(streams, tab/_).
pinned(streams, put_char/_).
pinned(streams, put_byte/_).
pinned(streams, get_char/_).
pinned(streams, get_byte/_).
pinned(streams, peek_char/_).
pinned(streams, flush_output/_).
pinned(streams, see/_).
pinned(streams, seen/_).
pinned(streams, seeing/_).
pinned(streams, tell/_).
pinned(streams, told/_).
pinned(streams, telling/_).
pinned(streams, append/1).          % Edinburgh append(File), not lists:append/3
pinned(streams, current_output/_).
pinned(streams, current_input/_).
pinned(streams, set_stream/_).
pinned(streams, stream_property/_).
pinned(streams, with_output_to/_).

pinned(filesystem, exists_file/_).
pinned(filesystem, exists_directory/_).
pinned(filesystem, delete_file/_).
pinned(filesystem, rename_file/_).
pinned(filesystem, directory_files/_).
pinned(filesystem, absolute_file_name/_).
pinned(filesystem, tmp_file/_).
pinned(filesystem, tmp_file_stream/_).
pinned(filesystem, working_directory/_).

%% A list in goal position is consult/1 on SWI ([file] loads file), and '.'/2
%% in goal position is dict access. Both are loading or evaluation, never a
%% goal an author needs. Found by the attestation harness feeding lists into
%% the control constructs.
pinned(loading, '[|]'/2).
pinned(loading, '.'/2).
pinned(loading, consult/_).
pinned(loading, use_module/_).
pinned(loading, ensure_loaded/_).
pinned(loading, include/1).
pinned(loading, load_files/_).
pinned(loading, make/0).

pinned(process, shell/_).
pinned(process, system/_).
pinned(process, process_create/_).
pinned(process, getenv/_).
pinned(process, setenv/_).
pinned(process, unsetenv/_).
pinned(process, halt/_).
pinned(process, abort/0).

pinned(foreign, load_foreign_library/_).
pinned(foreign, use_foreign_library/_).
pinned(foreign, open_shared_object/_).

pinned(threads, thread_create/_).
pinned(threads, thread_signal/_).
pinned(threads, mutex_create/_).
pinned(threads, message_queue_create/_).
pinned(threads, engine_create/_).
pinned(threads, engine_next/_).
pinned(threads, engine_yield/_).

pinned(network, tcp_socket/_).
pinned(network, tcp_connect/_).
pinned(network, tcp_open_socket/_).
pinned(network, http_open/_).
pinned(network, http_get/_).

pinned(flags_ops, set_prolog_flag/_).
pinned(flags_ops, current_prolog_flag/_).
pinned(flags_ops, create_prolog_flag/_).
pinned(flags_ops, op/3).

pinned(reflection, clause/_).
pinned(reflection, current_predicate/_).
pinned(reflection, predicate_property/_).
pinned(reflection, current_module/_).
pinned(reflection, module_property/_).
pinned(reflection, current_op/_).
pinned(reflection, source_file/_).
pinned(reflection, prolog_load_context/_).
pinned(reflection, prolog_current_frame/_).
pinned(reflection, prolog_frame_attribute/_).

pinned(parsing, read_term_from_atom/_).
pinned(parsing, term_to_atom/_).
pinned(parsing, atom_to_term/_).
pinned(parsing, term_string/_).
pinned(parsing, sformat/_).

pinned(destructive_state, setarg/_).
pinned(destructive_state, nb_setarg/_).
pinned(destructive_state, b_setval/_).
pinned(destructive_state, nb_setval/_).
pinned(destructive_state, b_getval/_).
pinned(destructive_state, nb_getval/_).
pinned(destructive_state, recorda/_).
pinned(destructive_state, recordz/_).
pinned(destructive_state, recorded/_).
pinned(destructive_state, erase/_).
pinned(destructive_state, flag/3).

%% format is pinned as a class and partially reopened by the application-layer
%% rule in the design doc (bound format string, inert directives only, atom or
%% string sink).
pinned(format, format/_).
pinned(format, format_atom/_).
pinned(format, with_output_to/_).

%% Added 2026-09-18 from the sandbox differential: predicates SWI's own
%% sandbox admits that Hornguard keeps out.
pinned(timing, sleep/_).
pinned(process, at_halt/_).
pinned(process, cancel_halt/_).
pinned(threads, thread_self/_).
pinned(reflection, statistics/_).
pinned(reflection, import_module/_).
pinned(reflection, default_module/_).
pinned(reflection, strip_module/_).
pinned(reflection, current_type/_).
pinned(reflection, current_arithmetic_function/_).
pinned(destructive_state, del_attr/_).
pinned(destructive_state, del_attrs/_).
pinned(streams, writeln/_).
%% write_ln/1 (library(backcomp)) writes to current output. SWI's sandbox
%% tolerates it because its hosts capture output; here it is the one output
%% predicate the generator let through, found by the attestation harness.
pinned(streams, write_ln/_).
pinned(streams, writef/_).
pinned(streams, portray_clause/_).
pinned(streams, print_message/_).
pinned(streams, print_message_lines/_).
pinned(streams, listing/_).
pinned(destructive_state, nb_current/_).

%% Two classes the walk cannot see through, pinned so no profile reopens them
%% by accident. A coroutine runs an author's goal later, at a unification the
%% host performs, in the host's own code path: the goal was judged, but when
%% and where it runs was not. Shared engine state is anything one author can
%% set that another author's query then reads: the random generator's seed,
%% the answer tables.
pinned(deferred_execution, freeze/_).
pinned(deferred_execution, when/_).
pinned(deferred_execution, call_residue_vars/_).
pinned(shared_state, set_random/_).
pinned(shared_state, abolish_all_tables/_).
pinned(shared_state, abolish_table_subgoals/_).
pinned(shared_state, abolish_module_tables/_).

%% Arithmetic functions are a second language inside the first, and the walk
%% checks the expressions of is/2 and the comparisons for these. The two that
%% read the clock hand an author the timing channel the `timing` pin closes for
%% sleep/1 and get_time/1. random/1 and random_float are deliberately not here:
%% randomness is admitted through the swi_random profile.
pinned_evaluable(timing, cputime/0).
pinned_evaluable(timing, realtime/0).
