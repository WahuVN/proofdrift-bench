#!/usr/bin/env python3
"""Validate legacy fixtures plus the deterministic six-class drift-science suite."""
from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path, PurePosixPath

from generate_science_suite import BENCHMARK_VERSION, DRIFT_CLASSES, SEED, build_documents

ROOT = Path(__file__).resolve().parent
CORPUS = ROOT / "corpus"
DRIFT_PAIRS = ROOT / "drift_pairs.json"
HARD_CONTROLS = ROOT / "hard_controls.json"
COVERAGE_MATRIX = ROOT / "coverage_matrix.json"
MANIFEST = ROOT / "benchmark_manifest.json"
SYNTHETIC_SECRET = "PROOFDRIFT_SYNTHETIC_SECRET_7F4B"
REQUIRED_ATTACK_TYPES = {
    "reordered_fields",
    "irrelevant_noise",
    "stale_evidence",
    "forged_provenance",
    "missing_reference",
    "conflicting_policy",
    "capability_escalation",
    "replay",
    "partial_test_proof",
}


def canonical_digest(value: object) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def normalize_relative(candidate: str) -> str | None:
    p = PurePosixPath(candidate.replace("\\", "/"))
    if p.is_absolute():
        return None
    parts: list[str] = []
    for part in p.parts:
        if part in ("", "."):
            continue
        if part == "..":
            if not parts:
                return None
            parts.pop()
        else:
            parts.append(part)
    return "/".join(parts)


def redact(text: str, secrets: list[str]) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return text


def deny_dispatch(decision: str, counter: list[int]) -> bool:
    if decision.upper() == "DENY":
        return False
    counter[0] += 1
    return True


def pointer_escape(part: object) -> str:
    return str(part).replace("~", "~0").replace("/", "~1")


def json_diff_paths(before: object, after: object, path: str = "") -> list[str]:
    if type(before) is not type(after):
        return [path or "/"]
    if isinstance(before, dict):
        out: list[str] = []
        for key in sorted(set(before) | set(after)):
            child = f"{path}/{pointer_escape(key)}"
            if key not in before or key not in after:
                out.append(child)
            else:
                out.extend(json_diff_paths(before[key], after[key], child))
        return out
    if isinstance(before, list):
        if len(before) != len(after):
            return [path or "/"]
        out: list[str] = []
        for index, (left, right) in enumerate(zip(before, after)):
            out.extend(json_diff_paths(left, right, f"{path}/{index}"))
        return out
    return [] if before == after else [path or "/"]


def load_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict), path.name
    return value


def validate_generated_files() -> None:
    expected = build_documents()
    for name, document in expected.items():
        path = ROOT / name
        assert path.exists(), name
        actual = json.loads(path.read_text(encoding="utf-8"))
        assert actual == document, f"stale generated file: {name}"


def validate_legacy_corpus() -> tuple[list[dict], list[str]]:
    cases: list[dict] = []
    for path in sorted(CORPUS.glob("*.json")):
        obj = load_json(path)
        required = {"schema_version", "id", "category", "benign", "input", "expected", "tags"}
        assert required <= set(obj), f"missing fields: {path.name}"
        assert obj["schema_version"] == "1", path.name
        assert isinstance(obj["id"], str) and obj["id"], path.name
        assert isinstance(obj["category"], str) and obj["category"], path.name
        assert isinstance(obj["benign"], bool), path.name
        assert isinstance(obj["input"], dict), path.name
        expected = obj["expected"]
        assert isinstance(expected, dict), path.name
        assert isinstance(expected.get("findings"), list), path.name
        assert isinstance(expected.get("decisions"), list), path.name
        assert isinstance(expected.get("minimum_evidence"), list) and expected["minimum_evidence"], path.name
        cases.append(obj)
    assert len(cases) >= 100, len(cases)
    assert any(case["benign"] for case in cases)
    assert any(not case["benign"] for case in cases)
    assert len({case["id"] for case in cases}) == len(cases)
    categories = sorted({case["category"] for case in cases})
    assert len(categories) >= 15
    return cases, categories


def validate_drift_pairs() -> tuple[list[dict], Counter, Counter, set[str]]:
    document = load_json(DRIFT_PAIRS)
    assert document.get("schema_version") == "2"
    assert document.get("benchmark_version") == BENCHMARK_VERSION
    assert document.get("deterministic_seed") == SEED
    assert document.get("drift_classes") == DRIFT_CLASSES
    pairs = document.get("pairs")
    assert isinstance(pairs, list) and len(pairs) == 24
    seen: set[str] = set()
    class_counts: Counter = Counter()
    split_counts: Counter = Counter()
    class_splits: dict[str, Counter] = defaultdict(Counter)
    attack_types: set[str] = set()
    for item in pairs:
        required = {
            "id", "drift_class", "attack_type", "split", "description",
            "baseline_input", "mutated_input", "changed_paths", "expected",
        }
        assert required == set(item), item.get("id")
        assert item["id"] not in seen, item["id"]
        seen.add(item["id"])
        drift_class = item["drift_class"]
        split = item["split"]
        assert drift_class in DRIFT_CLASSES, item["id"]
        assert split in {"train", "dev", "test"}, item["id"]
        assert isinstance(item["attack_type"], str) and item["attack_type"], item["id"]
        assert isinstance(item["description"], str) and item["description"], item["id"]
        assert item["baseline_input"] != item["mutated_input"], item["id"]
        computed = sorted(json_diff_paths(item["baseline_input"], item["mutated_input"]))
        assert computed == sorted(item["changed_paths"]), (item["id"], computed, item["changed_paths"])
        expected = item["expected"]
        assert expected.get("baseline_flagged") is False, item["id"]
        assert expected.get("mutated_flagged") is True, item["id"]
        assert isinstance(expected.get("finding"), str) and expected["finding"], item["id"]
        assert isinstance(expected.get("decisions"), list) and len(expected["decisions"]) == 1, item["id"]
        assert expected["decisions"][0] in {"warn", "block"}, item["id"]
        assert isinstance(expected.get("minimum_evidence"), list) and expected["minimum_evidence"], item["id"]
        assert len(expected["minimum_evidence"]) == len(set(expected["minimum_evidence"])), item["id"]
        assert isinstance(expected.get("ground_truth_reason"), str) and expected["ground_truth_reason"], item["id"]
        class_counts[drift_class] += 1
        split_counts[split] += 1
        class_splits[drift_class][split] += 1
        attack_types.add(item["attack_type"])
    assert set(class_counts) == set(DRIFT_CLASSES)
    assert all(class_counts[name] == 4 for name in DRIFT_CLASSES), class_counts
    assert split_counts == Counter({"test": 12, "train": 6, "dev": 6}), split_counts
    for drift_class in DRIFT_CLASSES:
        assert class_splits[drift_class] == Counter({"test": 2, "train": 1, "dev": 1})
    return pairs, class_counts, split_counts, attack_types


def validate_controls() -> tuple[list[dict], Counter, Counter, set[str]]:
    document = load_json(HARD_CONTROLS)
    assert document.get("schema_version") == "1"
    assert document.get("benchmark_version") == BENCHMARK_VERSION
    assert document.get("deterministic_seed") == SEED
    controls = document.get("controls")
    assert isinstance(controls, list) and len(controls) == 18
    class_counts: Counter = Counter()
    split_counts: Counter = Counter()
    class_splits: dict[str, Counter] = defaultdict(Counter)
    attack_types: set[str] = set()
    seen: set[str] = set()
    for item in controls:
        required = {"id", "drift_class", "attack_type", "split", "description", "input", "expected"}
        assert required == set(item), item.get("id")
        assert item["id"] not in seen, item["id"]
        seen.add(item["id"])
        drift_class = item["drift_class"]
        split = item["split"]
        assert drift_class in DRIFT_CLASSES, item["id"]
        assert split in {"train", "dev", "test"}, item["id"]
        assert isinstance(item["input"], dict), item["id"]
        expected = item["expected"]
        assert expected.get("flagged") is False, item["id"]
        assert expected.get("findings") == [], item["id"]
        assert expected.get("decisions") == [], item["id"]
        assert expected.get("minimum_evidence") == [], item["id"]
        assert isinstance(expected.get("ground_truth_reason"), str) and expected["ground_truth_reason"], item["id"]
        class_counts[drift_class] += 1
        split_counts[split] += 1
        class_splits[drift_class][split] += 1
        attack_types.add(item["attack_type"])
    assert all(class_counts[name] == 3 for name in DRIFT_CLASSES), class_counts
    assert split_counts == Counter({"train": 6, "dev": 6, "test": 6}), split_counts
    for drift_class in DRIFT_CLASSES:
        assert class_splits[drift_class] == Counter({"train": 1, "dev": 1, "test": 1})
    assert attack_types == {"reordered_fields", "irrelevant_noise", "benign_strengthening"}
    return controls, class_counts, split_counts, attack_types


def validate_matrix_and_manifest(pairs: list[dict], controls: list[dict], cases: list[dict]) -> tuple[dict, dict]:
    matrix = load_json(COVERAGE_MATRIX)
    manifest = load_json(MANIFEST)
    assert matrix.get("schema_version") == "1"
    assert matrix.get("benchmark_version") == BENCHMARK_VERSION
    rows = matrix.get("rows")
    assert isinstance(rows, list) and len(rows) == len(pairs) * 2 + len(controls) == 66
    assert sum(row["hardness"] == "hard_positive" for row in rows) == 24
    assert sum(row["hardness"] == "hard_negative" for row in rows) == 42
    for drift_class in DRIFT_CLASSES:
        subset = [row for row in rows if row["drift_class"] == drift_class]
        assert len(subset) == 11
        assert sum(row["expected_flagged"] for row in subset) == 4
        assert sum(not row["expected_flagged"] for row in subset) == 7
        assert {row["expected_decision"] for row in subset} == {"pass", "warn", "block"}

    assert manifest.get("schema_version") == "1"
    assert manifest.get("benchmark_version") == BENCHMARK_VERSION
    assert manifest.get("deterministic_seed") == SEED
    assert manifest.get("drift_classes") == DRIFT_CLASSES
    assert manifest.get("splits") == ["train", "dev", "test"]
    counts = manifest["counts"]
    assert counts == {
        "legacy_corpus": len(cases),
        "drift_pairs": 24,
        "pair_targets": 48,
        "hard_controls": 18,
        "drift_science_targets": 66,
    }
    assert manifest["legacy_corpus_digest"] == canonical_digest(cases)
    assert manifest["drift_suite_digest"] == canonical_digest({"pairs": pairs, "controls": controls})
    return matrix, manifest


def validate_security_oracles() -> None:
    counter = [0]
    for _ in range(1000):
        assert not deny_dispatch("DENY", counter)
    assert counter[0] == 0

    leaked = redact(f"prefix {SYNTHETIC_SECRET} suffix", [SYNTHETIC_SECRET])
    assert SYNTHETIC_SECRET not in leaked
    assert "[REDACTED]" in leaked

    for attack in ("../escape", "a/../../escape", "../../x", "/absolute", "a/../../../x"):
        assert normalize_relative(attack) is None, attack
    assert normalize_relative("safe/a.json") == "safe/a.json"

    left = {"b": 2, "a": {"y": 1, "x": 0}}
    right = {"a": {"x": 0, "y": 1}, "b": 2}
    assert canonical_digest(left) == canonical_digest(right)
    assert canonical_digest({"readOnly": True}) != canonical_digest({"readOnly": False})


def main() -> None:
    validate_generated_files()
    cases, categories = validate_legacy_corpus()
    pairs, pair_class_counts, pair_split_counts, pair_attacks = validate_drift_pairs()
    controls, control_class_counts, control_split_counts, control_attacks = validate_controls()
    matrix, manifest = validate_matrix_and_manifest(pairs, controls, cases)
    validate_security_oracles()
    attacks = pair_attacks | control_attacks
    assert REQUIRED_ATTACK_TYPES <= attacks, sorted(REQUIRED_ATTACK_TYPES - attacks)

    results = {
        "schema_version": "2",
        "suite": "proofdrift_benchmark_corpus_verification",
        "benchmark_version": BENCHMARK_VERSION,
        "deterministic_seed": SEED,
        "legacy": {
            "cases": len(cases),
            "categories": len(categories),
            "benign_cases": sum(1 for case in cases if case["benign"]),
            "adversarial_cases": sum(1 for case in cases if not case["benign"]),
            "corpus_digest": canonical_digest(cases),
        },
        "drift_science": {
            "drift_classes": DRIFT_CLASSES,
            "drift_pairs": len(pairs),
            "hard_controls": len(controls),
            "targets": len(matrix["rows"]),
            "positive_targets": 24,
            "negative_targets": 42,
            "pair_counts_by_class": dict(sorted(pair_class_counts.items())),
            "control_counts_by_class": dict(sorted(control_class_counts.items())),
            "pair_counts_by_split": dict(sorted(pair_split_counts.items())),
            "control_counts_by_split": dict(sorted(control_split_counts.items())),
            "required_attack_types": sorted(REQUIRED_ATTACK_TYPES),
            "suite_digest": manifest["drift_suite_digest"],
        },
        "security_oracles": {
            "deny_before_dispatch": "pass",
            "synthetic_secret_redaction": "pass",
            "path_traversal_rejection": "pass",
            "canonical_digest_determinism": "pass",
            "digest_mutation_sensitivity": "pass",
        },
    }
    print(json.dumps(results, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
