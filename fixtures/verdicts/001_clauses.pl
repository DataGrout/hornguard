%% Clause fixtures: what may be stored. The body is judged exactly as a goal;
%% the head may not shadow anything the judge reasons about.

%% Facts and pure rules are admitted. A clause may call its own head
%% (recursion); calling any other user predicate needs the host to say the
%% predicate exists in sandboxed space via the allow/1 option, so a fixture
%% cannot express it and a bare reference is an unknown.
clause_verdict(clause_fact,            iso, [iso], parent(tom, bob), admit).
clause_verdict(clause_pure_rule,       iso, [iso],
        (ancestor(A, C) :- ancestor(A, B), ancestor(B, C)), admit).
clause_verdict(clause_rule_needs,      iso, [iso],
        (chain(A, B) :- chain(B, A), member(A, [x])), admit_needs([profile(prologue)])).
clause_verdict(clause_rule_unknown,    iso, [iso],
        (grandparent(A, C) :- parent(A, B), parent(B, C)), refused(benign_miss, unknown)).

%% The body is a goal: the same refusals apply, at the same depths.
clause_verdict(clause_body_pinned,     iso, [iso],
        (leaky(V) :- current_prolog_flag(home, V)),
        refused(capability_probe, pinned(flags_ops))).
clause_verdict(clause_body_nested,     iso, [iso],
        (leaky(L) :- findall(V, current_prolog_flag(home, V), L)),
        refused(escape_attempt, pinned(flags_ops) + depth(1))).
clause_verdict(clause_body_unbound,    iso, [iso],
        (run(G) :- call(G)),
        refused(escape_attempt, unbound_goal)).
clause_verdict(clause_body_qualified,  iso, [iso],
        (sneaky :- system:true),
        refused(escape_attempt, qualified)).

%% Heads may not shadow control, pinned, or profile predicates.
clause_verdict(clause_head_pinned,     iso, [iso],
        (shell(_) :- true),
        refused(escape_attempt, head(pinned(process)))).
clause_verdict(clause_head_profile,    iso, [iso],
        (atom_length(_, 0) :- true),
        refused(escape_attempt, head(profile(iso)))).
clause_verdict(clause_head_control,    iso, [iso],
        (true :- fail),
        refused(escape_attempt, head(control))).
clause_verdict(clause_head_qualified,  iso, [iso],
        (user:foo :- true),
        refused(escape_attempt, head(qualified))).
clause_verdict(clause_head_unbound,    iso, [iso],
        (_ :- true),
        refused(escape_attempt, unbound_head)).

%% Directives are not clauses.
clause_verdict(clause_directive,       iso, [iso],
        (:- initialization(true)),
        refused(capability_probe, directive)).

%% DCG until the translation is judged post-expansion.
clause_verdict(clause_dcg_unsupported, iso, [iso],
        (greeting --> [hello]),
        refused(benign_miss, unsupported(dcg))).

%% More heads that may not be redefined: every pinned class, several
%% profiles, every control construct.
clause_verdict(clause_head_pinned_format,   iso, [iso], (format(_, _) :- true),
        refused(escape_attempt, head(pinned(format)))).
clause_verdict(clause_head_pinned_flags,    iso, [iso], (current_prolog_flag(_, _) :- true),
        refused(escape_attempt, head(pinned(flags_ops)))).
clause_verdict(clause_head_pinned_database, iso, [iso], assertz(_),
        refused(escape_attempt, head(pinned(database)))).
clause_verdict(clause_head_profile_member,  iso, [iso], (member(_, _) :- true),
        refused(escape_attempt, head(profile(prologue)))).
clause_verdict(clause_head_profile_findall, iso, [iso], (findall(_, _, _) :- true),
        refused(escape_attempt, head(profile(iso)))).
clause_verdict(clause_head_control_conj,    iso, [iso], (','(_, _) :- true),
        refused(escape_attempt, head(control))).
clause_verdict(clause_head_control_cut,     iso, [iso], (! :- true),
        refused(escape_attempt, head(control))).
clause_verdict(clause_head_control_neg,     iso, [iso], (\+ _ :- true),
        refused(escape_attempt, head(profile(iso)))).
clause_verdict(clause_head_control_colon,   iso, [iso], ((_ : _) :- true),
        refused(escape_attempt, head(qualified))).
