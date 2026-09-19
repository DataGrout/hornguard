%% Reader fixtures for the manifest-driven backends.
%%
%% Both Scryer and Trealla default to `double_quotes(chars)`, so the same
%% text means something different there than on SWI. That is the reason the
%% reader takes a backend at all.
%%
%% The agreement test in test/test_worker.pl feeds each of these to the real
%% engine when it is installed: the engine must read our canonical form into
%% the same term we meant, up to variable renaming.

reader(rd_sc_conj,      scryer, "a, b, c",                "','(a,','(b,c))").
reader(rd_sc_univ,      scryer, "G =.. [f, 1]",           "=..(G,[f,1])").
reader(rd_sc_clause,    scryer, "p(X) :- q(X), \\+ r(X)", ":-(p(X),','(q(X),\\+(r(X))))").
reader(rd_sc_caret,     scryer, "setof(X, Y^p(X,Y), L)",  "setof(X,^(Y,p(X,Y)),L)").
reader(rd_sc_ite,       scryer, "(a -> b ; c)",           ";(->(a,b),c)").
reader(rd_sc_curly,     scryer, "C = {a, b}",             "=(C,{','(a,b)})").
reader(rd_sc_arith,     scryer, "X is 1 + 2 * 3 - -1",    "is(X,-(+(1,*(2,3)),-1))").
reader(rd_sc_list,      scryer, "Z = [a|T]",              "=(Z,[a|T])").
reader(rd_sc_quoted,    scryer, "X = 'Hello World'",      "=(X,'Hello World')").
reader(rd_sc_neg_lit,   scryer, "X = - 1",                "=(X,-(1))").
reader(rd_sc_chars,     scryer, "Y = \"ab\"",             "=(Y,[a,b])").

reader(rd_tr_conj,      trealla, "a, b, c",               "','(a,','(b,c))").
reader(rd_tr_univ,      trealla, "G =.. [f, 1]",          "=..(G,[f,1])").
reader(rd_tr_clause,    trealla, "p(X) :- q(X), \\+ r(X)", ":-(p(X),','(q(X),\\+(r(X))))").
reader(rd_tr_caret,     trealla, "setof(X, Y^p(X,Y), L)", "setof(X,^(Y,p(X,Y)),L)").
reader(rd_tr_ite,       trealla, "(a -> b ; c)",          ";(->(a,b),c)").
reader(rd_tr_arith,     trealla, "X is 1 + 2 * 3 - -1",   "is(X,-(+(1,*(2,3)),-1))").
reader(rd_tr_list,      trealla, "Z = [a|T]",             "=(Z,[a|T])").
reader(rd_tr_quoted,    trealla, "X = 'Hello World'",     "=(X,'Hello World')").
reader(rd_tr_chars,     trealla, "Y = \"ab\"",            "=(Y,[a,b])").
