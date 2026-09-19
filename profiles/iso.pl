%% Profile `iso`: the pure ISO builtins.
%%
%% Each allow/2 fact is an attestation that the indicator is pure under
%% adversarial use on every backend that inherits this profile. Deliberately
%% absent although ISO defines them: assert*/retract*/abolish, every stream
%% predicate, op/3, set_prolog_flag/2, current_prolog_flag/2, halt/0,1,
%% char_conversion/2, clause/2, current_predicate/1, current_op/3. See
%% pinned.pl for why.
%%
%% meta_spec/2 uses SWI meta_predicate notation: 0 = goal, N = closure taking
%% N more arguments, ^ = existentially qualified goal, ? = not a goal.
%%
%% Profiles are data. The pack reads them with read_term/2; the multifile
%% declaration only makes several profile files consultable together for
%% inspection.

:- multifile allow/2, meta_spec/2.

%% Control
allow(iso, true/0).
allow(iso, fail/0).
allow(iso, false/0).
allow(iso, (!)/0).
allow(iso, (',')/2).
allow(iso, (;)/2).
allow(iso, (->)/2).
allow(iso, (\+)/1).
allow(iso, call/1).
allow(iso, call/2).
allow(iso, call/3).
allow(iso, call/4).
allow(iso, call/5).
allow(iso, call/6).
allow(iso, call/7).
allow(iso, call/8).
allow(iso, once/1).
allow(iso, forall/2).
allow(iso, catch/3).
allow(iso, throw/1).

%% Unification and term comparison
allow(iso, (=)/2).
allow(iso, (\=)/2).
allow(iso, (==)/2).
allow(iso, (\==)/2).
allow(iso, (@<)/2).
allow(iso, (@>)/2).
allow(iso, (@=<)/2).
allow(iso, (@>=)/2).
allow(iso, compare/3).
allow(iso, unify_with_occurs_check/2).
allow(iso, subsumes_term/2).

%% Type tests
allow(iso, var/1).
allow(iso, nonvar/1).
allow(iso, atom/1).
allow(iso, number/1).
allow(iso, integer/1).
allow(iso, float/1).
allow(iso, atomic/1).
allow(iso, compound/1).
allow(iso, callable/1).
allow(iso, ground/1).

%% Term inspection and construction
allow(iso, functor/3).
allow(iso, arg/3).
allow(iso, (=..)/2).
allow(iso, copy_term/2).
allow(iso, term_variables/2).

%% Arithmetic
allow(iso, (is)/2).
allow(iso, (=:=)/2).
allow(iso, (=\=)/2).
allow(iso, (<)/2).
allow(iso, (>)/2).
allow(iso, (=<)/2).
allow(iso, (>=)/2).

%% Atoms and characters
allow(iso, atom_codes/2).
allow(iso, atom_chars/2).
allow(iso, char_code/2).
allow(iso, atom_length/2).
allow(iso, atom_concat/3).
allow(iso, sub_atom/5).
allow(iso, number_codes/2).
allow(iso, number_chars/2).

%% All-solutions
allow(iso, findall/3).
allow(iso, findall/4).
allow(iso, bagof/3).
allow(iso, setof/3).

%% Sorting
allow(iso, sort/2).
allow(iso, keysort/2).

%% Meta-argument shapes for every allowed predicate that takes a goal. The
%% control constructs (,)/2, (;)/2, (->)/2, (*->)/2 and (^)/2 are structural:
%% the judge walks through them without counting depth, so they need no spec.
meta_spec(iso, '\\+'(0)).
meta_spec(iso, call(0)).
meta_spec(iso, call(1, ?)).
meta_spec(iso, call(2, ?, ?)).
meta_spec(iso, call(3, ?, ?, ?)).
meta_spec(iso, call(4, ?, ?, ?, ?)).
meta_spec(iso, call(5, ?, ?, ?, ?, ?)).
meta_spec(iso, call(6, ?, ?, ?, ?, ?, ?)).
meta_spec(iso, call(7, ?, ?, ?, ?, ?, ?, ?)).
meta_spec(iso, once(0)).
meta_spec(iso, forall(0, 0)).
meta_spec(iso, catch(0, ?, 0)).
meta_spec(iso, findall(?, 0, ?)).
meta_spec(iso, findall(?, 0, ?, ?)).
meta_spec(iso, bagof(?, ^, ?)).
meta_spec(iso, setof(?, ^, ?)).
