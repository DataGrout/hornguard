%% Profile `prologue`: the Prolog prologue proposal, which nearly every engine
%% implements and without which real rules cannot be written. Pure by
%% construction; the meta-predicates here carry most of the spec table.

:- multifile allow/2, meta_spec/2.

%% Lists
allow(prologue, append/3).
allow(prologue, member/2).
allow(prologue, memberchk/2).
allow(prologue, length/2).
allow(prologue, select/3).
allow(prologue, selectchk/3).
allow(prologue, subtract/3).
allow(prologue, intersection/3).
allow(prologue, union/3).
allow(prologue, delete/3).
allow(prologue, exclude/3).
allow(prologue, include/3).
allow(prologue, partition/4).
allow(prologue, nth0/3).
allow(prologue, nth1/3).
allow(prologue, last/2).
allow(prologue, reverse/2).
allow(prologue, msort/2).
allow(prologue, sort/4).
allow(prologue, predsort/3).
allow(prologue, list_to_set/2).
allow(prologue, sum_list/2).
allow(prologue, max_list/2).
allow(prologue, min_list/2).
allow(prologue, numlist/3).
allow(prologue, is_list/1).

%% Higher order
allow(prologue, maplist/2).
allow(prologue, maplist/3).
allow(prologue, maplist/4).
allow(prologue, maplist/5).
allow(prologue, maplist/6).
allow(prologue, maplist/7).
allow(prologue, foldl/4).
allow(prologue, foldl/5).
allow(prologue, foldl/6).
allow(prologue, ignore/1).
%% not/1 is the de facto alias of ISO's \+/1: same negation as failure, same
%% meta shape, never standardised because the name suggests classical negation.
allow(prologue, not/1).

%% Arithmetic helpers
allow(prologue, between/3).
allow(prologue, succ/2).
allow(prologue, plus/3).

%% Text
allow(prologue, atomic_list_concat/2).
allow(prologue, atomic_list_concat/3).

meta_spec(prologue, include(1, ?, ?)).
meta_spec(prologue, exclude(1, ?, ?)).
meta_spec(prologue, partition(1, ?, ?, ?)).
meta_spec(prologue, predsort(3, ?, ?)).
meta_spec(prologue, maplist(1, ?)).
meta_spec(prologue, maplist(2, ?, ?)).
meta_spec(prologue, maplist(3, ?, ?, ?)).
meta_spec(prologue, maplist(4, ?, ?, ?, ?)).
meta_spec(prologue, maplist(5, ?, ?, ?, ?, ?)).
meta_spec(prologue, maplist(6, ?, ?, ?, ?, ?, ?)).
meta_spec(prologue, foldl(3, ?, ?, ?)).
meta_spec(prologue, foldl(4, ?, ?, ?, ?)).
meta_spec(prologue, foldl(5, ?, ?, ?, ?, ?)).
meta_spec(prologue, ignore(0)).
meta_spec(prologue, not(0)).
