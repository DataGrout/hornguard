%% Reader fixtures: author text -> the canonical form the worker must emit.
%%
%%   reader(Id, Backend, Text, Canonical).
%%   reader(Id, Backend, Text, refused(reader(Why))).
%%
%% Canonical form is operator-free (every compound in functional notation),
%% atoms quoted where needed, the author's variable names kept so a host can
%% map bindings back, and anonymous variables printed as `_`. The same Text
%% read by the backend engine's own reader must canonicalise to the same
%% string; that agreement is what makes it safe to hand the engine the
%% canonical form instead of the author's text. The canonical form must also
%% be a fixed point: reading it back and canonicalising again yields itself.

reader(rd_conj,         swi, "a, b, c",                   "','(a,','(b,c))").
reader(rd_ops,          swi, "X is 1 + 2 * 3 - -1",       "is(X,-(+(1,*(2,3)),-1))").
reader(rd_neg_literal,  swi, "X = - 1",                   "=(X,-(1))").
reader(rd_neg_number,   swi, "X = -1",                    "=(X,-1)").
reader(rd_quoted_atom,  swi, "atom_length('it''s', N)",   "atom_length('it\\'s',N)").
reader(rd_quote_needed, swi, "X = 'Hello World'",         "=(X,'Hello World')").
reader(rd_list,         swi, "Z = [a|T]",                 "=(Z,[a|T])").
reader(rd_list_full,    swi, "Z = [a, b, c]",             "=(Z,[a,b,c])").
reader(rd_empty_list,   swi, "S = [], U = '[]'",          "','(=(S,[]),=(U,'[]'))").
reader(rd_curly,        swi, "C = {a, b}",                "=(C,{}(','(a,b)))").
reader(rd_curly_nested, swi, "C = {a, {b}}",              "=(C,{}(','(a,{}(b))))").
reader(rd_string_swi,   swi, "Y = \"str\"",               "=(Y,\"str\")").
reader(rd_codes_iso,    iso, "Y = \"ab\"",                "=(Y,[97,98])").
reader(rd_chars_scryer, scryer, "Y = \"ab\"",             "=(Y,[a,b])").
reader(rd_char_code,    swi, "C = 0'a",                   "=(C,97)").
reader(rd_named_kept,   swi, "p(X, Y, X)",                "p(X,Y,X)").
reader(rd_anonymous,    swi, "p(_, _Foo, X)",             "p(_,_Foo,X)").
reader(rd_clause,       swi, "p(X) :- q(X), \\+ r(X)",    ":-(p(X),','(q(X),\\+(r(X))))").
reader(rd_caret,        swi, "setof(X, Y^p(X,Y), L)",     "setof(X,^(Y,p(X,Y)),L)").
reader(rd_if_then,      swi, "(a -> b ; c)",              ";(->(a,b),c)").
reader(rd_univ,         swi, "G =.. [f, 1]",              "=..(G,[f,1])").
reader(rd_escapes,      swi, "X = 'a\\nb'",               "=(X,'a\\nb')").
reader(rd_big_int,      swi, "X = 123456789012345678901234567890", "=(X,123456789012345678901234567890)").
reader(rd_float,        swi, "X = 1.5e10",                "=(X,15000000000.0)").
reader(rd_float_short,  swi, "X = 0.1",                   "=(X,0.1)").
reader(rd_float_long,   swi, "X = 0.30000000000000004",   "=(X,0.30000000000000004)").
reader(rd_float_exp,    swi, "X = 1.0e22",                "=(X,1.0e+22)").
reader(rd_float_neg,    swi, "X = -2.5e-7",               "=(X,-2.5e-07)").
reader(rd_op_as_atom,   swi, "X = (+), Y = (:-)",         "','(=(X,+),=(Y,:-))").
reader(rd_nested_ops,   swi, "X = a:b:c",                 "=(X,:(a,:(b,c)))").
%% An author's own '$VAR'/1 terms are data and stay data: a writer in
%% numbervars mode would print '$VAR'('Shell') as the variable Shell, and the
%% engine would read a variable where the judge saw ground data.
reader(rd_dollar_var,   swi, "p('$VAR'('Shell'), '$VAR'(1), '$VAR'('_'))",
        "p('$VAR'('Shell'),'$VAR'(1),'$VAR'('_'))").

%% Refused at the reader.
reader(rd_syntax,       swi, "foo(",                      refused(reader(syntax_error(_)))).
reader(rd_two_terms,    swi, "a. b.",                     refused(reader(term_count))).
reader(rd_quasi,        swi, "X = {|html||<b>x</b>|}",     refused(reader(_))).
