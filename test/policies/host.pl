%% A host policy: SWI backend, the common profiles, sandboxed predicates the
%% host has stored, one trusted host predicate with a meta spec, one without.
backend(swi).
profiles([iso, prologue, swi_lists]).
option(strict_negation(true)).
option(defer_unknown(true)).
allow(customer_tier/2).
allow(region_of/2).
trust(lookup_price/3, none).
trust(with_tenant/2, with_tenant(?, 0)).
