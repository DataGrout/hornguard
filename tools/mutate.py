#!/usr/bin/env python3
"""Mutation harness for the judge.

Each mutation disables one rule of the walk in a copy of prolog/hornguard.pl
and runs the fixture suite against the copy under a time limit. A mutant that
the suite still passes (or that neither fails nor times out) is a blind spot:
some rule the fixtures do not exercise. The harness exits non-zero if any
mutant survives.

Run: python3 tools/mutate.py            (or: make mutation)
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "prolog", "hornguard.pl")
TIME_LIMIT_S = 120

# (name, what it disables, old, new). `old` must occur exactly once.
MUTATIONS = [
    ("no_pinned_check", "pinned classes are never consulted",
     "    (   hg_pinned(PinClass, Ind)\n    ->  hg_pinned_report_class(PinClass, D, Class),",
     "    (   fail, hg_pinned(PinClass, Ind)\n    ->  hg_pinned_report_class(PinClass, D, Class),"),
    ("unbound_goal_admitted", "an unbound goal in call position is admitted",
     "hg_goal(Var, _, _, _, _) :-\n    var(Var), !,\n    throw(hg_refused(instantiation_error, escape_attempt, unbound_goal)).",
     "hg_goal(Var, _, _, N, N) :-\n    var(Var), !."),
    ("qualified_goal_walked", "module-qualified goals are walked as their inner goal",
     "hg_goal(_:_, _, _, _, _) :- !,\n    throw(hg_refused(permission_error(execute, goal, (:)/2), escape_attempt, qualified)).",
     "hg_goal(_:G, D, Ctx, N0, N) :- !,\n    hg_goal(G, D, Ctx, N0, N)."),
    ("closure_not_completed", "closures are judged as written, not at their called arity",
     "    hg_complete_closure(A, K, G),\n    hg_goal(G, D, Ctx, N0, N).\nhg_apply_mode(_, _, _, _, N, N).",
     "    K = K, A = G,\n    hg_goal(G, D, Ctx, N0, N).\nhg_apply_mode(_, _, _, _, N, N)."),
    ("depth_not_counted", "meta-argument nesting does not increase depth",
     "    D1 is D + 1,\n    Spec =.. [_|Modes],",
     "    D1 = D,\n    Spec =.. [_|Modes],"),
    ("caret_treated_as_data", "existentially qualified goal arguments are not judged",
     "hg_apply_mode(^, A, D, Ctx, N0, N) :- !,\n    hg_strip_existential(A, G),\n    hg_goal(G, D, Ctx, N0, N).",
     "hg_apply_mode(^, _, _, _, N, N) :- !."),
    ("goal_mode_treated_as_data", "goal arguments (mode 0) are not judged",
     "hg_apply_mode(0, A, D, Ctx, N0, N) :- !,\n    hg_goal(A, D, Ctx, N0, N).",
     "hg_apply_mode(0, _, _, _, N, N) :- !."),
    ("head_may_shadow_pinned", "a clause head may redefine a pinned predicate",
     "    ;   hg_pinned(Class, Ind)\n    ->  throw(hg_refused(permission_error(modify, static_procedure, Ind), escape_attempt, head(pinned(Class))))",
     "    ;   fail, hg_pinned(Class, Ind)\n    ->  throw(hg_refused(permission_error(modify, static_procedure, Ind), escape_attempt, head(pinned(Class))))"),
    ("head_may_shadow_profile", "a clause head may redefine a profile predicate",
     "    ;   hg_allow(Profile, Ind)\n    ->  throw(hg_refused(permission_error(modify, static_procedure, Ind), escape_attempt, head(profile(Profile))))",
     "    ;   fail, hg_allow(Profile, Ind)\n    ->  throw(hg_refused(permission_error(modify, static_procedure, Ind), escape_attempt, head(profile(Profile))))"),
    ("directive_stored", "directives are stored as clauses",
     "hg_clause((:- _), _, _) :- !,\n    throw(hg_refused(permission_error(execute, directive, (:-)/1), capability_probe, directive)).",
     "hg_clause((:- _), _, []) :- !."),
    ("negation_not_a_negative_edge", "\\\\+ does not count for stratification",
     "hg_negative_context(\\+ G, G).\n", ""),
    ("aggregation_not_a_negative_edge", "findall does not count for stratification",
     "hg_negative_context(findall(_, G, _), G).\n", ""),
    ("floundering_ignores_later_use", "a variable introduced by negation is never flagged",
     "        \\+ hg_var_memberchk(V, Bound),\n        hg_var_memberchk(V, Later)",
     "        \\+ hg_var_memberchk(V, Bound),\n        fail, hg_var_memberchk(V, Later)"),
    ("meta_gap_not_checked", "an allowed predicate the engine declares meta needs no spec",
     "        ;   hg_engine_meta_gap(Ctx, G)\n        ->  throw(",
     "        ;   fail, hg_engine_meta_gap(Ctx, G)\n        ->  throw("),
    ("cyclic_terms_walked", "cyclic terms are walked (must time out)",
     "    (   acyclic_term(Term)\n    ->  catch(Judgment, E, hg_exception_verdict(E, Verdict))",
     "    (   true\n    ->  catch(Judgment, E, hg_exception_verdict(E, Verdict))"),
    ("trust_spec_ignored", "trusted predicates' goal arguments are not judged",
     "    ;   hg_trusted(Ind, Ctx, Spec)\n    ->  hg_apply_spec(Spec, G, D, Ctx, N0, N)",
     "    ;   hg_trusted(Ind, Ctx, _Spec)\n    ->  N = N0"),
    ("reflection_not_recon", "reflection is classified like any other pin",
     "hg_pinned_report_class(reflection, _, reconnaissance) :- !.\n", ""),
    ("control_head_allowed", "a clause may define a control construct",
     "    (   hg_control_indicator(Ind)\n    ->  throw(",
     "    (   fail, hg_control_indicator(Ind)\n    ->  throw("),
    ("defer_ignores_the_manifest", "deferral does not ask what the engine defines",
     "hg_deferrable(Ctx, G, Ind) :-\n    Ctx = ctx(_, _, _, _, true),\n    \\+ hg_engine_defines(Ctx, G, Ind).",
     "hg_deferrable(Ctx, _, _) :-\n    Ctx = ctx(_, _, _, _, true)."),
]


def run_suite(workdir):
    """Run the fixture and policy suites against the mutated copy."""
    goal = ("use_module(library(time)), "
            "catch(call_with_time_limit(%d, (load_files(['test/test_hornguard.pl','test/test_policy.pl'],[]), run_tests)), E, "
            "(print_message(error, E), halt(3)))" % TIME_LIMIT_S)
    proc = subprocess.run(
        ["swipl", "-q", "-g", goal, "-t", "halt"],
        cwd=workdir, capture_output=True, text=True, timeout=TIME_LIMIT_S + 30)
    return proc.returncode, proc.stdout + proc.stderr


def main():
    src = open(SRC).read()
    survivors, killed = [], []
    for name, what, old, new in MUTATIONS:
        if src.count(old) != 1:
            print(f"?? {name}: pattern occurs {src.count(old)} times; harness is stale")
            survivors.append(name + " (stale pattern)")
            continue
        with tempfile.TemporaryDirectory() as tmp:
            shutil.copytree(ROOT, tmp, dirs_exist_ok=True,
                            ignore=shutil.ignore_patterns(".git", "target", "crates"))
            mutated = os.path.join(tmp, "prolog", "hornguard.pl")
            open(mutated, "w").write(src.replace(old, new, 1))
            try:
                code, out = run_suite(tmp)
            except subprocess.TimeoutExpired:
                code, out = 124, "timeout"
        failed = re.search(r"(\d+) tests? failed", out)
        if code != 0 or failed or "timeout" in out or "time_limit_exceeded" in out:
            n = failed.group(1) if failed else ("timeout" if code in (3, 124) else "error")
            killed.append(name)
            print(f"killed  {name:32s} {what}  [{n}]")
        else:
            survivors.append(name)
            print(f"SURVIVED {name:31s} {what}")
    print(f"\n{len(killed)} killed, {len(survivors)} survived")
    if survivors:
        print("blind spots:", ", ".join(survivors))
        sys.exit(1)


if __name__ == "__main__":
    main()
