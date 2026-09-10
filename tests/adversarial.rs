use proofdrift_security_bench::*;
use proptest::prelude::*;
use serde_json::json;
use std::path::Path;
#[test]
fn corpus_has_at_least_100_cases_and_expectations() {
    let c = load_cases(&Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus")).unwrap();
    assert!(c.len() >= 100);
    assert!(c.iter().any(|x| x.benign));
    assert!(c.iter().any(|x| !x.benign));
    for x in c {
        assert_eq!(x.schema_version, "1");
        assert!(!x.id.is_empty());
        assert!(!x.category.is_empty());
        assert!(!x.expected.minimum_evidence.is_empty());
        if x.benign {
            assert!(x
                .expected
                .findings
                .iter()
                .all(|f| !f.starts_with("critical:")));
        }
    }
}
#[test]
fn deny_never_dispatches() {
    let mut d = FakeDownstream::default();
    for _ in 0..100 {
        assert!(!broker_call("DENY", &mut d));
    }
    assert_eq!(d.dispatch_count, 0);
}
#[test]
fn approval_is_one_time() {
    let mut s = ApprovalStore::default();
    assert!(s.consume("approval-1"));
    assert!(!s.consume("approval-1"));
}
#[test]
fn synthetic_secret_is_redacted() {
    let secret = "PROOFDRIFT_SYNTHETIC_SECRET_7F4B";
    let out = redact(&format!("headers token={} end", secret), &[secret]);
    assert!(!out.contains(secret));
    assert!(out.contains("[REDACTED]"));
}
#[test]
fn unknown_backend_never_reports_l2() {
    assert_ne!(enforcement_level(false, false), 2);
    assert_ne!(enforcement_level(false, true), 2);
    assert_eq!(enforcement_level(true, true), 2);
}
#[test]
fn canonical_hash_ignores_object_key_order() {
    let a = json!({"b":2,"a":{"y":1,"x":0}});
    let b = json!({"a":{"x":0,"y":1},"b":2});
    assert_eq!(canonical_digest(&a), canonical_digest(&b));
}
#[test]
fn mutation_changes_digest() {
    let a = json!({"tool":{"name":"read","mutating":false}});
    let b = json!({"tool":{"name":"read","mutating":true}});
    assert_ne!(canonical_digest(&a), canonical_digest(&b));
}
#[test]
fn traversal_rejected() {
    let root = Path::new("sandbox");
    for p in ["../escape", "a/../../escape", "/absolute", "a/../../../x"] {
        assert!(normalize_relative(root, Path::new(p)).is_none(), "{}", p);
    }
    assert!(normalize_relative(root, Path::new("safe/a.json")).is_some());
}
proptest! {
 #[test] fn digest_deterministic_for_json_strings(s in ".{0,128}"){ let v=json!({"value":s,"n":7}); prop_assert_eq!(canonical_digest(&v),canonical_digest(&v)); }
 #[test] fn redaction_never_leaves_exact_secret(prefix in ".{0,32}", suffix in ".{0,32}"){ let secret="SYNTH_SECRET_X9"; let input=format!("{}{}{}",prefix,secret,suffix); prop_assert!(!redact(&input,&[secret]).contains(secret)); }
 #[test] fn parent_prefix_cannot_escape(n in 1usize..12){ let p=format!("{}escape", "../".repeat(n)); prop_assert!(normalize_relative(Path::new("root"),Path::new(&p)).is_none()); }
}
