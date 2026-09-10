#!/usr/bin/env python3
"""Release-quality invariants for ProofDrift Bench v3."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CORPUS = ROOT / "corpus"
PAIRS = ROOT / "drift_pairs.json"
CONTROLS = ROOT / "hard_controls.json"
MANIFEST = ROOT / "benchmark_manifest.json"
COVERAGE = ROOT / "coverage_matrix.json"
CRITICAL_LEGACY = {
    "tampered_receipt",
    "approval_concurrent_replay",
    "missing_provenance_trusted",
    "policy_digest_mismatch",
    "decision_request_digest_mismatch",
    "toctou_executable_swap",
    "evidence_reorder",
    "evidence_deleted_event",
}
DRIFT_CLASSES = {
    "provenance_drift",
    "capability_drift",
    "policy_drift",
    "runtime_drift",
    "patch_impact_drift",
    "test_proof_drift",
}
SPLITS = {"train", "dev", "test"}


def load(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(value, dict):
        raise SystemExit(f"{path.name}: root must be an object")
    return value


def canonical_digest(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def main() -> int:
    corpus_paths = sorted(CORPUS.glob("*.json"))
    corpus = [load(path) for path in corpus_paths]
    categories = {case.get("category") for case in corpus}
    missing_legacy = CRITICAL_LEGACY - categories
    if missing_legacy:
        raise SystemExit(f"missing critical legacy categories: {sorted(missing_legacy)}")
    if len({case.get("id") for case in corpus}) != len(corpus):
        raise SystemExit("duplicate legacy benchmark case id")
    for path, case in zip(corpus_paths, corpus, strict=True):
        if case.get("schema_version") != "1":
            raise SystemExit(f"{path.name}: unsupported legacy schema_version")
        if not case.get("expected", {}).get("minimum_evidence"):
            raise SystemExit(f"{path.name}: expected.minimum_evidence is empty")

    pair_doc = load(PAIRS)
    control_doc = load(CONTROLS)
    manifest = load(MANIFEST)
    coverage = load(COVERAGE)
    pairs = pair_doc.get("pairs")
    controls = control_doc.get("controls")
    if pair_doc.get("schema_version") != "2" or pair_doc.get("benchmark_version") != "3":
        raise SystemExit("drift_pairs.json must be schema v2 / benchmark v3")
    if control_doc.get("schema_version") != "1" or control_doc.get("benchmark_version") != "3":
        raise SystemExit("hard_controls.json must be schema v1 / benchmark v3")
    if not isinstance(pairs, list) or not isinstance(controls, list):
        raise SystemExit("science suite arrays are malformed")
    if len({item.get("id") for item in pairs}) != len(pairs):
        raise SystemExit("duplicate drift-pair id")
    if len({item.get("id") for item in controls}) != len(controls):
        raise SystemExit("duplicate hard-control id")

    pair_classes = {item.get("drift_class") for item in pairs}
    control_classes = {item.get("drift_class") for item in controls}
    pair_splits = {item.get("split") for item in pairs}
    control_splits = {item.get("split") for item in controls}
    if pair_classes != DRIFT_CLASSES or control_classes != DRIFT_CLASSES:
        raise SystemExit("all six drift classes must have pair and hard-control coverage")
    if pair_splits != SPLITS or control_splits != SPLITS:
        raise SystemExit("train/dev/test coverage is required for pairs and hard controls")

    for pair in pairs:
        expected = pair.get("expected") or {}
        if expected.get("baseline_flagged") is not False or expected.get("mutated_flagged") is not True:
            raise SystemExit(f"{pair.get('id')}: pair labels must encode safe-to-risky direction")
        if not expected.get("finding") or not expected.get("decisions") or not expected.get("minimum_evidence"):
            raise SystemExit(f"{pair.get('id')}: incomplete semantic oracle")
        if not expected.get("ground_truth_reason"):
            raise SystemExit(f"{pair.get('id')}: missing ground_truth_reason")
        if not pair.get("changed_paths"):
            raise SystemExit(f"{pair.get('id')}: changed_paths is empty")
    for control in controls:
        expected = control.get("expected") or {}
        if expected.get("flagged") is not False:
            raise SystemExit(f"{control.get('id')}: hard control must be negative")
        if expected.get("findings") != [] or expected.get("decisions") != []:
            raise SystemExit(f"{control.get('id')}: hard control must not carry positive oracle outputs")
        if not expected.get("ground_truth_reason"):
            raise SystemExit(f"{control.get('id')}: missing ground_truth_reason")

    counts = manifest.get("counts") or {}
    expected_counts = {
        "legacy_corpus": len(corpus),
        "drift_pairs": len(pairs),
        "pair_targets": len(pairs) * 2,
        "hard_controls": len(controls),
        "drift_science_targets": len(pairs) * 2 + len(controls),
    }
    for key, value in expected_counts.items():
        if counts.get(key) != value:
            raise SystemExit(f"manifest count mismatch for {key}: {counts.get(key)} != {value}")
    if set(manifest.get("drift_classes") or []) != DRIFT_CLASSES:
        raise SystemExit("manifest drift class set mismatch")
    if set(manifest.get("splits") or []) != SPLITS:
        raise SystemExit("manifest split set mismatch")
    rows = coverage.get("rows")
    if not isinstance(rows, list) or len(rows) != expected_counts["drift_science_targets"]:
        raise SystemExit("coverage_matrix.json row count does not match the science target count")
    if {row.get("drift_class") for row in rows} != DRIFT_CLASSES:
        raise SystemExit("coverage_matrix.json does not cover all drift classes")
    if {row.get("split") for row in rows} != SPLITS:
        raise SystemExit("coverage_matrix.json does not cover train/dev/test")
    if {row.get("side") for row in rows} != {"baseline", "mutated", "control"}:
        raise SystemExit("coverage_matrix.json must cover pair baselines, mutations, and controls")

    science_document = {"pairs": pairs, "controls": controls}
    evidence = {
        "gate": "proofdrift_bench_security_release_gate",
        "status": "pass",
        "benchmark_version": manifest.get("benchmark_version"),
        "deterministic_seed": manifest.get("deterministic_seed"),
        "legacy_cases": len(corpus),
        "legacy_categories": len(categories),
        "legacy_benign": sum(1 for case in corpus if case.get("benign")),
        "legacy_adversarial": sum(1 for case in corpus if not case.get("benign")),
        "drift_pairs": len(pairs),
        "hard_controls": len(controls),
        "science_targets": len(pairs) * 2 + len(controls),
        "drift_classes": sorted(DRIFT_CLASSES),
        "splits": sorted(SPLITS),
        "pair_ground_truth_reasons": sum(bool((item.get("expected") or {}).get("ground_truth_reason")) for item in pairs),
        "control_ground_truth_reasons": sum(bool((item.get("expected") or {}).get("ground_truth_reason")) for item in controls),
        "legacy_corpus_digest": canonical_digest(corpus),
        "science_oracle_digest": canonical_digest(science_document),
        "manifest_drift_suite_digest": manifest.get("drift_suite_digest"),
    }
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
