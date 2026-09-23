%% A host whose fact store is a set of platform predicates that authors add
%% clauses to: attribute/3 is trusted for calls and declared author-defined,
%% so an author's attribute/3 fact is a permitted head, while lookup_price/3
%% stays a plain trusted predicate no author may define.
backend(swi).
profiles([iso, prologue]).
option(defer_unknown(true)).
trust(attribute/3, none).
trust(lookup_price/3, none).
author_defines(attribute/3).
author_defines(note/1).
