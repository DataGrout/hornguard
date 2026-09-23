//! Integration tests: every one of these drives a real judge worker.
//!
//! The crate is a client, so there is nothing worth testing against a mock —
//! a mock would only assert that the crate agrees with itself. These run the
//! pack from the repository this crate lives in.

use hornguard::{Class, Error, Hornguard, Need, Verdict};
use std::path::PathBuf;

/// The pack is two directories up from this crate.
fn home() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn judge() -> Hornguard {
    Hornguard::builder()
        .home(home())
        .profiles(["iso", "prologue"])
        .spawn()
        .expect("spawn judge worker")
}

#[test]
fn handshake_reports_the_engine_and_profiles() {
    let hg = judge();
    assert_eq!(hg.engine(), Some("swi"));
    assert!(hg.engine_version().is_some());
    assert!(hg.profiles_at_start().iter().any(|p| p == "iso"));
}

#[test]
fn a_pure_goal_is_admitted_with_canonical_text() {
    let mut hg = judge();
    let v = hg.judge_goal("findall(X, member(X, [a, b]), L)").unwrap();
    assert!(v.is_admitted());
    // Operator-free, and the author's variable names survive so bindings can
    // be mapped back.
    assert_eq!(v.canonical(), Some("findall(X,member(X,[a,b]),L)"));
}

#[test]
fn a_pinned_predicate_in_a_meta_argument_is_an_escape_attempt() {
    let mut hg = judge();
    let v = hg
        .judge_goal("findall(H, current_prolog_flag(home, H), _)")
        .unwrap();
    match v {
        Verdict::Refused {
            class,
            rule,
            depth,
            reason,
        } => {
            assert_eq!(class, Class::EscapeAttempt);
            assert!(class.is_adversarial());
            assert_eq!(rule, "pinned(flags_ops)");
            assert_eq!(depth, 1);
            assert!(reason.contains("current_prolog_flag/2"));
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn the_same_predicate_at_the_top_level_is_only_a_probe() {
    let mut hg = judge();
    let v = hg.judge_goal("current_prolog_flag(home, H)").unwrap();
    match v {
        Verdict::Refused { class, depth, .. } => {
            assert_eq!(class, Class::CapabilityProbe);
            assert_eq!(depth, 0);
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_constructed_goal_is_refused_at_the_sink() {
    let mut hg = judge();
    let v = hg.judge_goal("G =.. [shell, 'rm -rf /'], call(G)").unwrap();
    match v {
        Verdict::Refused { class, rule, .. } => {
            assert_eq!(class, Class::EscapeAttempt);
            assert_eq!(rule, "unbound_goal");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_missing_profile_is_a_need_not_a_refusal() {
    let mut hg = Hornguard::builder()
        .home(home())
        .profiles(["iso"])
        .spawn()
        .unwrap();
    let v = hg.judge_goal("string_concat(a, b, C)").unwrap();
    assert_eq!(v.needs(), &[Need::Profile("swi".into())]);
    assert!(!v.is_admitted(), "a need is not yet a yes");
    assert!(v.canonical().is_some(), "the term itself is fine");
}

#[test]
fn defer_unknown_reports_predicates_the_host_has_not_stored() {
    let mut hg = Hornguard::builder()
        .home(home())
        .profiles(["iso"])
        .defer_unknown(true)
        .spawn()
        .unwrap();
    let v = hg.judge_clause("p(X) :- q(X)").unwrap();
    assert_eq!(v.needs(), &[Need::Predicate("q/1".into())]);
}

#[test]
fn a_clause_head_may_not_shadow_a_pinned_predicate() {
    let mut hg = judge();
    let v = hg.judge_clause("shell(_) :- true").unwrap();
    match v {
        Verdict::Refused { class, rule, .. } => {
            assert_eq!(class, Class::EscapeAttempt);
            assert_eq!(rule, "head(pinned(process))");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_program_that_recurses_through_negation_has_no_single_meaning() {
    let mut hg = Hornguard::builder()
        .home(home())
        .profiles(["iso"])
        .spawn()
        .unwrap();
    let v = hg
        .judge_program("p(X) :- q(X), \\+ r(X).\nr(X) :- q(X), \\+ p(X).\nq(1).")
        .unwrap();
    match v {
        Verdict::Refused { class, rule, .. } => {
            // Not a threat: the author gets this back to fix.
            assert_eq!(class, Class::Semantics);
            assert!(!class.is_adversarial());
            assert!(rule.starts_with("unstratified("));
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn unparseable_text_is_refused_by_the_reader_not_the_engine() {
    let mut hg = judge();
    let v = hg.judge_goal("foo(").unwrap();
    match v {
        Verdict::Refused { class, rule, .. } => {
            assert_eq!(class, Class::Evasion);
            assert!(rule.starts_with("reader("));
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn two_terms_where_one_was_asked_for_is_refused() {
    let mut hg = judge();
    let v = hg.judge_goal("a. b.").unwrap();
    match v {
        Verdict::Refused { class, rule, .. } => {
            assert_eq!(class, Class::Evasion);
            assert_eq!(rule, "reader(term_count)");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_trusted_host_predicate_still_has_its_goal_arguments_judged() {
    let mut hg = Hornguard::builder()
        .home(home())
        .profiles(["iso"])
        .trust([("with_tenant/2", "with_tenant(?,0)")])
        .spawn()
        .unwrap();
    let v = hg.judge_goal("with_tenant(t, halt)").unwrap();
    match v {
        Verdict::Refused { rule, depth, .. } => {
            assert_eq!(rule, "pinned(process)");
            assert_eq!(depth, 1, "the goal argument was judged one level deeper");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn judged_dynamic_dispatch_rewrites_the_sink_instead_of_refusing() {
    let mut hg = Hornguard::builder()
        .home(home())
        .profiles(["iso", "prologue"])
        .dynamic_dispatch(true)
        .spawn()
        .unwrap();
    let v = hg
        .judge_goal("member(G, Goals), call(G), maplist(P, Xs)")
        .unwrap();
    assert!(
        v.is_admitted(),
        "admit_with is a yes for the rewritten term"
    );
    match &v {
        Verdict::AdmitWith { canonical } => {
            assert!(v_contains(canonical, "hornguard_call(G)"));
            assert!(v_contains(canonical, "maplist(hornguard_call(P),Xs)"));
        }
        other => panic!("expected admit_with, got {other:?}"),
    }
    // A goal the judge can see is still refused statically, at its depth.
    let v = hg
        .judge_goal("findall(H, current_prolog_flag(home, H), L)")
        .unwrap();
    assert!(matches!(v, Verdict::Refused { .. }));
    // And without the option the default holds.
    let mut strict = judge();
    let v = strict.judge_goal("call(G)").unwrap();
    match v {
        Verdict::Refused { rule, .. } => assert_eq!(rule, "unbound_goal"),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn v_contains(canonical: &str, needle: &str) -> bool {
    canonical.replace(' ', "").contains(needle)
}

#[test]
fn a_clause_may_not_define_a_trusted_host_predicate() {
    let mut hg = Hornguard::builder()
        .home(home())
        .profiles(["iso"])
        .trust([("lookup_price/3", "none")])
        .spawn()
        .unwrap();
    // The trusted definition is the one whose body is never walked; a clause
    // in sandboxed space with that head would stand in for it.
    let v = hg.judge_clause("lookup_price(_, _, 0) :- true").unwrap();
    match v {
        Verdict::Refused { class, rule, .. } => {
            assert_eq!(class, Class::EscapeAttempt);
            assert_eq!(rule, "head(trusted)");
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_policy_file_configures_the_worker() {
    let policy = home().join("test").join("policies").join("host.pl");
    let mut hg = Hornguard::builder()
        .home(home())
        .policy(&policy)
        .spawn()
        .unwrap();
    // host.pl allows customer_tier/2 and trusts lookup_price/3.
    let v = hg
        .judge_goal("customer_tier(C, gold), lookup_price(C, _, _)")
        .unwrap();
    assert!(v.is_admitted(), "got {v:?}");
    // And it does not reopen anything pinned.
    assert!(hg.judge_goal("shell('true')").unwrap().is_refused());
}

#[test]
fn profiles_can_be_listed_and_reloaded() {
    let mut hg = judge();
    let before = hg.profiles().unwrap();
    assert!(before.iter().any(|p| p == "prologue"));
    hg.load_profiles([home().join("profiles")]).unwrap();
    let after = hg.profiles().unwrap();
    assert_eq!(before, after);
}

#[test]
fn the_worker_survives_a_request_it_cannot_answer() {
    let mut hg = judge();
    // A policy that does not exist is the worker's error, not a dead worker.
    let err = hg.load_policy("/nonexistent/policy.pl").unwrap_err();
    assert!(matches!(err, Error::Worker { .. }), "got {err:?}");
    hg.ping().expect("worker still answering");
    assert!(hg.judge_goal("atom(a)").unwrap().is_admitted());
}

#[test]
fn a_missing_pack_is_reported_clearly() {
    let err = Hornguard::builder()
        .home("/nonexistent/hornguard")
        .spawn()
        .unwrap_err();
    match err {
        Error::PackNotFound { tried } => assert!(!tried.is_empty()),
        other => panic!("expected PackNotFound, got {other:?}"),
    }
}

#[test]
fn ids_stay_in_step_across_many_requests() {
    let mut hg = judge();
    for i in 0..50 {
        let v = hg.judge_goal(&format!("atom_length(a{i}, N)")).unwrap();
        assert!(v.is_admitted(), "request {i}: {v:?}");
    }
}

#[test]
fn workers_are_independent() {
    let mut a = Hornguard::builder()
        .home(home())
        .profiles(["iso"])
        .spawn()
        .unwrap();
    let mut b = Hornguard::builder()
        .home(home())
        .profiles(["iso", "prologue"])
        .spawn()
        .unwrap();
    // member/2 is in prologue: same text, different answers, no shared state.
    assert!(!a.judge_goal("member(X, [a])").unwrap().is_admitted());
    assert!(b.judge_goal("member(X, [a])").unwrap().is_admitted());
}
