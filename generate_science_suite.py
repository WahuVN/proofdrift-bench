#!/usr/bin/env python3
"""Generate the deterministic drift-science suite and its manifests."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SEED = 20260911
BENCHMARK_VERSION = "3"
DRIFT_CLASSES = [
    "provenance_drift",
    "capability_drift",
    "policy_drift",
    "runtime_drift",
    "patch_impact_drift",
    "test_proof_drift",
]


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(value: object) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def pair(
    ident: str,
    drift_class: str,
    attack_type: str,
    split: str,
    description: str,
    baseline_input: dict,
    mutated_input: dict,
    changed_paths: list[str],
    finding: str,
    decision: str,
    minimum_evidence: list[str],
    reason: str,
) -> dict:
    return {
        "id": ident,
        "drift_class": drift_class,
        "attack_type": attack_type,
        "split": split,
        "description": description,
        "baseline_input": baseline_input,
        "mutated_input": mutated_input,
        "changed_paths": changed_paths,
        "expected": {
            "baseline_flagged": False,
            "mutated_flagged": True,
            "finding": finding,
            "decisions": [decision],
            "minimum_evidence": minimum_evidence,
            "ground_truth_reason": reason,
        },
    }


def control(
    ident: str,
    drift_class: str,
    attack_type: str,
    split: str,
    description: str,
    input_value: dict,
    reason: str,
) -> dict:
    return {
        "id": ident,
        "drift_class": drift_class,
        "attack_type": attack_type,
        "split": split,
        "description": description,
        "input": input_value,
        "expected": {
            "flagged": False,
            "findings": [],
            "decisions": [],
            "minimum_evidence": [],
            "ground_truth_reason": reason,
        },
    }


def stable_order(rows: list[dict]) -> list[dict]:
    return sorted(
        rows,
        key=lambda row: hashlib.sha256(f"{SEED}:{row['id']}".encode("utf-8")).hexdigest(),
    )


def build_pairs() -> list[dict]:
    rows = [
        pair(
            "prov-floating-source-ref", "provenance_drift", "floating_source_ref", "train",
            "An immutable source revision becomes a floating branch reference.",
            {"provenance": {"source": "https://example.invalid/tool.git", "revision": "0123456789abcdef0123456789abcdef01234567"}},
            {"provenance": {"source": "https://example.invalid/tool.git", "revision": "main"}},
            ["/provenance/revision"], "high:PROVENANCE_DRIFT", "warn",
            ["source_ref", "resolved_revision"],
            "Only the revision mutates; immutable-to-floating provenance must be detected.",
        ),
        pair(
            "prov-stale-evidence", "provenance_drift", "stale_evidence", "dev",
            "Fresh provenance evidence becomes older than its declared maximum age.",
            {"provenance": {"evidence_age_seconds": 120, "max_age_seconds": 3600}},
            {"provenance": {"evidence_age_seconds": 7200, "max_age_seconds": 3600}},
            ["/provenance/evidence_age_seconds"], "high:PROVENANCE_DRIFT", "warn",
            ["evidence_timestamp", "max_age"],
            "The evidence exceeds the explicit freshness bound while all other context is fixed.",
        ),
        pair(
            "prov-forged-attestation", "provenance_drift", "forged_provenance", "test",
            "A trusted provenance issuer is replaced with a self-asserted issuer.",
            {"provenance": {"attestation": {"issuer": "trusted-build", "signature_valid": True}}},
            {"provenance": {"attestation": {"issuer": "self-asserted", "signature_valid": True}}},
            ["/provenance/attestation/issuer"], "critical:PROVENANCE_DRIFT", "block",
            ["attestation_issuer", "signature_verification"],
            "A syntactically valid signature is insufficient when the provenance issuer is not trusted.",
        ),
        pair(
            "prov-missing-source-ref", "provenance_drift", "missing_reference", "test",
            "A resolved provenance record loses the reference that binds it to its source.",
            {"provenance": {"source_ref": "sha256:aaaaaaaa", "resolved_revision": "0123456789abcdef0123456789abcdef01234567"}},
            {"provenance": {"source_ref": "", "resolved_revision": "0123456789abcdef0123456789abcdef01234567"}},
            ["/provenance/source_ref"], "critical:PROVENANCE_DRIFT", "block",
            ["source_ref", "resolved_revision"],
            "Missing source binding prevents the revision from being traced to verifiable provenance.",
        ),
        pair(
            "cap-read-to-write", "capability_drift", "capability_escalation", "train",
            "A workspace read capability expands to write while resource scope stays fixed.",
            {"capability": {"action": "fs.read", "resource": "workspace/**"}},
            {"capability": {"action": "fs.write", "resource": "workspace/**"}},
            ["/capability/action"], "critical:CAPABILITY_DRIFT", "block",
            ["capability_before", "capability_after"],
            "The action changes from read to write with no compensating scope restriction.",
        ),
        pair(
            "cap-scope-global", "capability_drift", "scope_escalation", "dev",
            "A bounded read scope expands to a global resource selector.",
            {"capability": {"action": "fs.read", "resource": "workspace/src/**"}},
            {"capability": {"action": "fs.read", "resource": "**"}},
            ["/capability/resource"], "high:CAPABILITY_DRIFT", "warn",
            ["capability_before", "capability_after"],
            "The capability verb is unchanged but the resource set becomes globally broader.",
        ),
        pair(
            "cap-discovery-to-exec", "capability_drift", "discovery_to_execution", "test",
            "Passive discovery gains direct execution permission.",
            {"discovery": {"mode": "metadata", "execution_allowed": False}},
            {"discovery": {"mode": "metadata", "execution_allowed": True}},
            ["/discovery/execution_allowed"], "critical:CAPABILITY_DRIFT", "block",
            ["capability_before", "capability_after"],
            "Execution is a material new capability and must not be inferred from discovery access.",
        ),
        pair(
            "cap-network-method", "capability_drift", "network_method_escalation", "test",
            "A read-only network request becomes state-changing while destination remains fixed.",
            {"network_capability": {"method": "GET", "host": "api.example.invalid"}},
            {"network_capability": {"method": "POST", "host": "api.example.invalid"}},
            ["/network_capability/method"], "high:CAPABILITY_DRIFT", "warn",
            ["capability_before", "capability_after"],
            "Changing GET to POST adds state-changing authority without changing the host.",
        ),
        pair(
            "policy-digest-mismatch", "policy_drift", "policy_digest_mismatch", "train",
            "The policy digest bound to a decision no longer matches dispatch.",
            {"policy": {"decision_digest": "aaaaaaaa", "dispatch_digest": "aaaaaaaa"}},
            {"policy": {"decision_digest": "aaaaaaaa", "dispatch_digest": "bbbbbbbb"}},
            ["/policy/dispatch_digest"], "critical:POLICY_DRIFT", "block",
            ["policy_digest", "decision_hash"],
            "Dispatch must be governed by the same policy version that produced the decision.",
        ),
        pair(
            "policy-conflict", "policy_drift", "conflicting_policy", "dev",
            "A required deny is overridden by an effective allow.",
            {"policy": {"required_decision": "deny", "effective_decision": "deny"}},
            {"policy": {"required_decision": "deny", "effective_decision": "allow"}},
            ["/policy/effective_decision"], "critical:POLICY_DRIFT", "block",
            ["required_policy", "effective_policy"],
            "The effective policy conflicts with the required deny and would weaken enforcement.",
        ),
        pair(
            "policy-enforcement-downgrade", "policy_drift", "policy_downgrade", "test",
            "Strict enforcement silently degrades to advisory mode.",
            {"policy": {"required_enforcement": "strict", "effective_enforcement": "strict"}},
            {"policy": {"required_enforcement": "strict", "effective_enforcement": "advisory"}},
            ["/policy/effective_enforcement"], "critical:POLICY_DRIFT", "block",
            ["required_policy", "effective_policy"],
            "Advisory enforcement is weaker than the required strict mode.",
        ),
        pair(
            "policy-missing-ref", "policy_drift", "missing_reference", "test",
            "A decision loses the policy reference needed to audit its governing rules.",
            {"policy": {"policy_ref": "sha256:policy-aaaa", "decision": "allow"}},
            {"policy": {"policy_ref": "", "decision": "allow"}},
            ["/policy/policy_ref"], "high:POLICY_DRIFT", "warn",
            ["policy_ref", "decision_hash"],
            "An unbound decision cannot prove which policy produced it.",
        ),
        pair(
            "runtime-request-binding", "runtime_drift", "request_binding_mismatch", "train",
            "The request digest at dispatch no longer matches the decision-bound digest.",
            {"runtime": {"decision_request_digest": "aaaaaaaa", "dispatch_request_digest": "aaaaaaaa"}},
            {"runtime": {"decision_request_digest": "aaaaaaaa", "dispatch_request_digest": "bbbbbbbb"}},
            ["/runtime/dispatch_request_digest"], "critical:RUNTIME_DRIFT", "block",
            ["request_digest", "decision_hash"],
            "Runtime dispatch must execute exactly the request that was evaluated.",
        ),
        pair(
            "runtime-replay", "runtime_drift", "replay", "dev",
            "A monotonic execution sequence is replaced by a previously consumed sequence.",
            {"runtime": {"previous_sequence": 10, "current_sequence": 11}},
            {"runtime": {"previous_sequence": 10, "current_sequence": 10}},
            ["/runtime/current_sequence"], "critical:RUNTIME_DRIFT", "block",
            ["sequence", "consumption_record"],
            "A non-increasing sequence indicates replay or rollback of an already observed request.",
        ),
        pair(
            "runtime-stale-decision", "runtime_drift", "stale_evidence", "test",
            "A fresh runtime decision ages beyond its time-to-live before dispatch.",
            {"runtime": {"decision_age_seconds": 10, "ttl_seconds": 300}},
            {"runtime": {"decision_age_seconds": 301, "ttl_seconds": 300}},
            ["/runtime/decision_age_seconds"], "high:RUNTIME_DRIFT", "warn",
            ["decision_timestamp", "dispatch_timestamp"],
            "The decision is stale at dispatch and may no longer reflect current runtime state.",
        ),
        pair(
            "runtime-command-swap", "runtime_drift", "toctou_command_swap", "test",
            "The command approved by policy is swapped before dispatch.",
            {"runtime": {"approved_argv": ["git", "status"], "dispatch_argv": ["git", "status"]}},
            {"runtime": {"approved_argv": ["git", "status"], "dispatch_argv": ["git", "reset", "--hard"]}},
            ["/runtime/dispatch_argv"], "critical:RUNTIME_DRIFT", "block",
            ["approved_argv", "dispatch_argv"],
            "A time-of-check/time-of-use command swap changes the executed operation after approval.",
        ),
        pair(
            "patch-critical-file", "patch_impact_drift", "critical_file_expansion", "train",
            "A documentation-only patch expands to authentication runtime code.",
            {"patch": {"changed_files": ["docs/guide.md"]}},
            {"patch": {"changed_files": ["docs/guide.md", "src/auth.rs"]}},
            ["/patch/changed_files"], "critical:PATCH_IMPACT_DRIFT", "block",
            ["patch_before", "patch_after"],
            "Adding authentication code materially increases patch impact and requires stronger proof.",
        ),
        pair(
            "patch-scope-escape", "patch_impact_drift", "scope_escape", "dev",
            "A patch that was inside its declared scope now modifies an out-of-scope production file.",
            {"patch": {"allowed_scope": "src/**", "changed_path": "src/lib.rs"}},
            {"patch": {"allowed_scope": "src/**", "changed_path": "infra/prod.tf"}},
            ["/patch/changed_path"], "critical:PATCH_IMPACT_DRIFT", "block",
            ["declared_scope", "changed_paths"],
            "The changed path no longer falls under the scope that was evaluated.",
        ),
        pair(
            "patch-dependency-policy", "patch_impact_drift", "dependency_policy_change", "test",
            "A dependency update moves from allowlisted to non-allowlisted provenance.",
            {"patch": {"dependency_change": {"name": "serde", "allowed": True}}},
            {"patch": {"dependency_change": {"name": "serde", "allowed": False}}},
            ["/patch/dependency_change/allowed"], "high:PATCH_IMPACT_DRIFT", "warn",
            ["dependency_before", "dependency_after"],
            "The dependency change crosses the explicit allowlist boundary.",
        ),
        pair(
            "patch-generated-to-runtime", "patch_impact_drift", "generated_to_runtime", "test",
            "A generated artifact is replaced by runtime source under the same review context.",
            {"patch": {"artifact_kind": "generated", "path": "generated/schema.json"}},
            {"patch": {"artifact_kind": "runtime_source", "path": "generated/schema.json"}},
            ["/patch/artifact_kind"], "high:PATCH_IMPACT_DRIFT", "warn",
            ["patch_before", "patch_after"],
            "Runtime source carries a different execution risk than generated data.",
        ),
        pair(
            "test-claimed-not-observed", "test_proof_drift", "claimed_not_observed", "train",
            "A test result changes from observed execution to an unobserved claim.",
            {"test_proof": {"command": "cargo test", "observed": True}},
            {"test_proof": {"command": "cargo test", "observed": False}},
            ["/test_proof/observed"], "critical:TEST_PROOF_DRIFT", "block",
            ["test_command", "execution_receipt"],
            "A claimed result without observed execution is not valid test proof.",
        ),
        pair(
            "test-partial-proof", "test_proof_drift", "partial_test_proof", "dev",
            "Complete required test execution becomes only a partial subset.",
            {"test_proof": {"required": 100, "passed": 100}},
            {"test_proof": {"required": 100, "passed": 60}},
            ["/test_proof/passed"], "high:TEST_PROOF_DRIFT", "warn",
            ["required_tests", "observed_tests"],
            "Only part of the required test set is proven to have passed.",
        ),
        pair(
            "test-stale-source-digest", "test_proof_drift", "stale_test_proof", "test",
            "The tested source digest no longer matches the current source digest.",
            {"test_proof": {"source_digest": "aaaaaaaa", "proof_digest": "aaaaaaaa"}},
            {"test_proof": {"source_digest": "aaaaaaaa", "proof_digest": "bbbbbbbb"}},
            ["/test_proof/proof_digest"], "critical:TEST_PROOF_DRIFT", "block",
            ["source_digest", "proof_digest"],
            "Test proof for a different source revision cannot establish the current patch result.",
        ),
        pair(
            "test-missing-receipt", "test_proof_drift", "missing_reference", "test",
            "An observed test loses its execution receipt reference.",
            {"test_proof": {"observed": True, "execution_receipt": "exec:1234"}},
            {"test_proof": {"observed": True, "execution_receipt": ""}},
            ["/test_proof/execution_receipt"], "high:TEST_PROOF_DRIFT", "warn",
            ["test_command", "execution_receipt"],
            "Without a receipt, the claimed observation cannot be traced to an execution record.",
        ),
    ]
    return stable_order(rows)


def build_controls() -> list[dict]:
    rows: list[dict] = []
    safe_by_class = {
        "provenance_drift": (
            {"provenance": {"revision": "0123456789abcdef0123456789abcdef01234567", "source_ref": "sha256:aaaa", "attestation": {"signature_valid": True, "issuer": "trusted-build"}, "evidence_age_seconds": 30, "max_age_seconds": 3600}},
            "The provenance remains immutable, trusted, referenced, and fresh.",
        ),
        "capability_drift": (
            {"capability": {"action": "fs.read", "resource": "workspace/src/**"}, "discovery": {"execution_allowed": False}, "network_capability": {"method": "GET", "host": "api.example.invalid"}},
            "Read-only bounded capabilities remain unchanged and do not imply execution.",
        ),
        "policy_drift": (
            {"policy": {"decision_digest": "aaaaaaaa", "dispatch_digest": "aaaaaaaa", "required_decision": "deny", "effective_decision": "deny", "required_enforcement": "strict", "effective_enforcement": "strict", "policy_ref": "sha256:policy"}},
            "Policy binding, decision, enforcement, and reference are mutually consistent.",
        ),
        "runtime_drift": (
            {"runtime": {"decision_request_digest": "aaaaaaaa", "dispatch_request_digest": "aaaaaaaa", "previous_sequence": 10, "current_sequence": 11, "decision_age_seconds": 5, "ttl_seconds": 300, "approved_argv": ["git", "status"], "dispatch_argv": ["git", "status"]}},
            "The runtime request is fresh, monotonic, and identical to the approved command.",
        ),
        "patch_impact_drift": (
            {"patch": {"changed_files": ["docs/guide.md"], "allowed_scope": "docs/**", "changed_path": "docs/guide.md", "dependency_change": {"name": "serde", "allowed": True}, "artifact_kind": "generated"}},
            "The patch stays inside declared low-risk scope with allowlisted dependencies.",
        ),
        "test_proof_drift": (
            {"test_proof": {"command": "cargo test", "observed": True, "required": 100, "passed": 100, "source_digest": "aaaaaaaa", "proof_digest": "aaaaaaaa", "execution_receipt": "exec:1234"}},
            "The complete test proof is observed, current, and bound to an execution receipt.",
        ),
    }
    for drift_class in DRIFT_CLASSES:
        base, reason = safe_by_class[drift_class]
        reordered = json.loads(json.dumps(base))
        # Reconstruct the top-level map in an unusual order. JSON object order must not affect semantics.
        if len(reordered) == 1:
            top_key = next(iter(reordered))
            nested = reordered[top_key]
            if isinstance(nested, dict):
                reordered[top_key] = dict(reversed(list(nested.items())))
        rows.append(control(
            f"{drift_class}-reordered", drift_class, "reordered_fields", "train",
            "Equivalent safe input with fields deliberately reordered.", reordered,
            f"Field order is non-semantic. {reason}",
        ))
        noisy = json.loads(json.dumps(base))
        noisy["metadata"] = {"note": "irrelevant-noise", "trace_label": "synthetic-control"}
        rows.append(control(
            f"{drift_class}-noise", drift_class, "irrelevant_noise", "dev",
            "Equivalent safe input with irrelevant metadata noise.", noisy,
            f"Unrelated metadata must not create drift. {reason}",
        ))
        strengthened = json.loads(json.dumps(base))
        strengthened["assurance"] = {"additional_validation": True}
        rows.append(control(
            f"{drift_class}-strengthening", drift_class, "benign_strengthening", "test",
            "Equivalent safe input with an additional assurance-only field.", strengthened,
            f"Additional assurance is a hard negative, not a security regression. {reason}",
        ))
    return stable_order(rows)


def load_legacy_corpus() -> list[dict]:
    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted((ROOT / "corpus").glob("*.json"))
    ]


def build_documents() -> dict[str, object]:
    pairs = build_pairs()
    controls = build_controls()
    legacy = load_legacy_corpus()
    pair_doc = {
        "schema_version": "2",
        "benchmark_version": BENCHMARK_VERSION,
        "deterministic_seed": SEED,
        "drift_classes": DRIFT_CLASSES,
        "pairs": pairs,
    }
    control_doc = {
        "schema_version": "1",
        "benchmark_version": BENCHMARK_VERSION,
        "deterministic_seed": SEED,
        "controls": controls,
    }
    matrix = []
    for item in pairs:
        expected = item["expected"]
        matrix.append({
            "case_id": item["id"], "side": "baseline", "drift_class": item["drift_class"],
            "attack_type": item["attack_type"], "split": item["split"], "hardness": "hard_negative",
            "expected_flagged": False, "expected_decision": "pass",
        })
        matrix.append({
            "case_id": item["id"], "side": "mutated", "drift_class": item["drift_class"],
            "attack_type": item["attack_type"], "split": item["split"], "hardness": "hard_positive",
            "expected_flagged": True, "expected_decision": expected["decisions"][0],
        })
    for item in controls:
        matrix.append({
            "case_id": item["id"], "side": "control", "drift_class": item["drift_class"],
            "attack_type": item["attack_type"], "split": item["split"], "hardness": "hard_negative",
            "expected_flagged": False, "expected_decision": "pass",
        })
    matrix = sorted(matrix, key=lambda row: (row["drift_class"], row["attack_type"], row["case_id"], row["side"]))
    matrix_doc = {
        "schema_version": "1",
        "benchmark_version": BENCHMARK_VERSION,
        "rows": matrix,
    }
    pair_by_class = Counter(item["drift_class"] for item in pairs)
    control_by_class = Counter(item["drift_class"] for item in controls)
    pair_by_split = Counter(item["split"] for item in pairs)
    control_by_split = Counter(item["split"] for item in controls)
    manifest = {
        "schema_version": "1",
        "benchmark": "proofdrift_detector_quality",
        "benchmark_version": BENCHMARK_VERSION,
        "deterministic_seed": SEED,
        "drift_classes": DRIFT_CLASSES,
        "splits": ["train", "dev", "test"],
        "suite_files": {
            "legacy_corpus": "corpus/*.json",
            "drift_pairs": "drift_pairs.json",
            "hard_controls": "hard_controls.json",
            "coverage_matrix": "coverage_matrix.json",
        },
        "counts": {
            "legacy_corpus": len(legacy),
            "drift_pairs": len(pairs),
            "pair_targets": len(pairs) * 2,
            "hard_controls": len(controls),
            "drift_science_targets": len(pairs) * 2 + len(controls),
        },
        "pair_counts_by_class": dict(sorted(pair_by_class.items())),
        "control_counts_by_class": dict(sorted(control_by_class.items())),
        "pair_counts_by_split": dict(sorted(pair_by_split.items())),
        "control_counts_by_split": dict(sorted(control_by_split.items())),
        "legacy_corpus_digest": digest(legacy),
        "drift_suite_digest": digest({"pairs": pairs, "controls": controls}),
    }
    return {
        "drift_pairs.json": pair_doc,
        "hard_controls.json": control_doc,
        "coverage_matrix.json": matrix_doc,
        "benchmark_manifest.json": manifest,
    }


def render(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="fail if committed generated files are stale")
    args = parser.parse_args()
    documents = build_documents()
    stale = []
    for name, document in documents.items():
        path = ROOT / name
        expected = render(document)
        if args.check:
            actual = path.read_text(encoding="utf-8") if path.exists() else ""
            if actual != expected:
                stale.append(name)
        else:
            path.write_text(expected, encoding="utf-8", newline="\n")
    if stale:
        print("stale generated benchmark files: " + ", ".join(stale))
        return 2
    if args.check:
        print("generated benchmark files are deterministic and up to date")
    else:
        print("generated deterministic benchmark science suite")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
