#!/usr/bin/env python3
"""Verify the committed detector-quality gate and optionally score real predictions."""
from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path

from evaluate_quality import (
    BENCHMARK_VERSION,
    ground_truth_predictions,
    load_targets,
    read_predictions,
    score,
    select_targets,
)

ROOT = Path(__file__).resolve().parent
THRESHOLDS_PATH = ROOT / "benchmark_thresholds.json"
BASELINE_PATH = ROOT / "benchmark_baseline.json"


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.name}: root must be an object")
    return value


def gate_failures(result: dict, thresholds: dict) -> list[str]:
    pairs = result.get("drift_pairs") or {}
    checks = [
        ("fpr", result["overall"]["fpr"], "max", thresholds["max_fpr"]),
        ("fnr", result["overall"]["fnr"], "max", thresholds["max_fnr"]),
        ("pair_accuracy", pairs.get("pair_accuracy"), "min", thresholds["min_pair_accuracy"]),
        ("pair_baseline_fpr", pairs.get("baseline_false_positive_rate"), "max", thresholds["max_pair_baseline_fpr"]),
        ("pair_fnr", pairs.get("mutated_false_negative_rate"), "max", thresholds["max_pair_fnr"]),
    ]
    failures = []
    for name, value, direction, limit in checks:
        if value is None:
            failures.append(f"{name}=missing")
        elif direction == "max" and value > limit:
            failures.append(f"{name}={value:.6f}>{limit:.6f}")
        elif direction == "min" and value < limit:
            failures.append(f"{name}={value:.6f}<{limit:.6f}")
    return failures


def validate_config(threshold_doc: dict, baseline: dict) -> dict:
    if threshold_doc.get("schema_version") != "1" or baseline.get("schema_version") != "1":
        raise ValueError("unsupported quality-gate schema_version")
    if threshold_doc.get("benchmark_version") != BENCHMARK_VERSION:
        raise ValueError("benchmark_thresholds.json version does not match scorer")
    if baseline.get("benchmark_version") != BENCHMARK_VERSION:
        raise ValueError("benchmark_baseline.json version does not match scorer")
    if threshold_doc.get("focus") != "drift" or baseline.get("focus") != "drift":
        raise ValueError("quality gate must be scoped to drift science targets")
    thresholds = threshold_doc.get("thresholds")
    required = {
        "max_fpr",
        "max_fnr",
        "min_pair_accuracy",
        "max_pair_baseline_fpr",
        "max_pair_fnr",
    }
    if not isinstance(thresholds, dict) or set(thresholds) != required:
        raise ValueError("benchmark_thresholds.json has an unexpected threshold set")
    for name, value in thresholds.items():
        if not isinstance(value, (int, float)) or isinstance(value, bool) or not 0.0 <= float(value) <= 1.0:
            raise ValueError(f"threshold {name} must be in [0,1]")
    return {name: float(value) for name, value in thresholds.items()}


def verify_harness(targets: list, thresholds: dict, baseline: dict) -> dict:
    oracle = ground_truth_predictions(targets)
    current = score(targets, oracle)
    pairs = current["drift_pairs"]
    if current["target_set_digest"] != baseline["target_set_digest"]:
        raise ValueError("drift target_set_digest changed; review labels/corpus and update baseline intentionally")
    positives = sum(target.expected_flagged for target in targets)
    negatives = len(targets) - positives
    expected_counts = {
        "targets": len(targets),
        "positive_targets": positives,
        "negative_targets": negatives,
        "drift_pairs": pairs["pairs"],
        "hard_controls": current["hard_controls"]["targets"],
    }
    for key, value in expected_counts.items():
        if baseline.get(key) != value:
            raise ValueError(f"baseline count mismatch for {key}: expected {baseline.get(key)}, current {value}")
    expected_metrics = baseline["oracle_harness_baseline"]
    current_metrics = {
        "fpr": current["overall"]["fpr"],
        "fnr": current["overall"]["fnr"],
        "pair_accuracy": pairs["pair_accuracy"],
        "pair_baseline_fpr": pairs["baseline_false_positive_rate"],
        "pair_fnr": pairs["mutated_false_negative_rate"],
    }
    if current_metrics != expected_metrics:
        raise ValueError(f"oracle harness baseline changed: {current_metrics}")
    if gate_failures(current, thresholds):
        raise ValueError("perfect harness oracle unexpectedly fails committed thresholds")

    degraded = dict(oracle)
    pair_baselines = [target for target in targets if target.pair_side == "baseline"]
    pair_mutated = [target for target in targets if target.pair_side == "mutated"]
    if len(pair_baselines) < 3 or len(pair_mutated) < 2:
        raise ValueError("not enough pair targets to exercise FPR/FNR threshold sensitivity")
    for target in pair_baselines[:3]:
        degraded[target.target_id] = replace(degraded[target.target_id], flagged=True, score=1.0)
    for target in pair_mutated[:2]:
        degraded[target.target_id] = replace(degraded[target.target_id], flagged=False, score=0.0)
    degraded_result = score(targets, degraded)
    degraded_failures = gate_failures(degraded_result, thresholds)
    required_failure_prefixes = {"fpr=", "fnr=", "pair_accuracy=", "pair_baseline_fpr=", "pair_fnr="}
    observed_prefixes = {failure.split("=", 1)[0] + "=" for failure in degraded_failures}
    if not required_failure_prefixes <= observed_prefixes:
        raise ValueError(f"quality gate failed to catch deliberate regression: {degraded_failures}")
    return {
        "schema_version": "1",
        "benchmark_version": BENCHMARK_VERSION,
        "target_set_digest": current["target_set_digest"],
        "counts": expected_counts,
        "baseline_metrics": current_metrics,
        "thresholds": thresholds,
        "deliberate_regression": {
            "flipped_pair_baselines": 3,
            "flipped_pair_mutated": 2,
            "fpr": degraded_result["overall"]["fpr"],
            "fnr": degraded_result["overall"]["fnr"],
            "pair_accuracy": degraded_result["drift_pairs"]["pair_accuracy"],
            "failures": degraded_failures,
        },
        "status": "pass",
        "note": "Harness baseline verifies scorer/corpus integrity only; it is not detector performance.",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("predictions", nargs="?", type=Path, help="optional real detector predictions JSONL")
    args = parser.parse_args()
    threshold_doc = load_json(THRESHOLDS_PATH)
    baseline = load_json(BASELINE_PATH)
    thresholds = validate_config(threshold_doc, baseline)
    targets = select_targets(load_targets(), "drift", "all")

    harness_report = verify_harness(targets, thresholds, baseline)
    if args.predictions is None:
        print(json.dumps(harness_report, indent=2, sort_keys=True))
        return 0

    result = score(targets, read_predictions(args.predictions))
    failures = gate_failures(result, thresholds)
    report = {
        "schema_version": "1",
        "benchmark_version": BENCHMARK_VERSION,
        "target_set_digest": result["target_set_digest"],
        "metrics": {
            "fpr": result["overall"]["fpr"],
            "fnr": result["overall"]["fnr"],
            "pair_accuracy": result["drift_pairs"]["pair_accuracy"],
            "pair_baseline_fpr": result["drift_pairs"]["baseline_false_positive_rate"],
            "pair_fnr": result["drift_pairs"]["mutated_false_negative_rate"],
        },
        "thresholds": thresholds,
        "failures": failures,
        "status": "fail" if failures else "pass",
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 2 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
