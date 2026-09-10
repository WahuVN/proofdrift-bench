#!/usr/bin/env python3
"""Implementation-neutral detector-quality scorer for ProofDrift Bench."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CORPUS = ROOT / "corpus"
DRIFT_PAIRS = ROOT / "drift_pairs.json"
HARD_CONTROLS = ROOT / "hard_controls.json"
BENCHMARK_VERSION = "3"
TARGET_ID_DOMAIN = b"proofdrift-bench-v3\0"


@dataclass(frozen=True)
class Target:
    source_id: str
    target_id: str
    suite: str
    category: str
    input: object
    expected_flagged: bool
    expected_findings: tuple[str, ...]
    expected_decisions: tuple[str, ...]
    minimum_evidence: tuple[str, ...]
    drift_class: str | None = None
    attack_type: str | None = None
    split: str = "legacy"
    pair_id: str | None = None
    pair_side: str | None = None
    ground_truth_reason: str | None = None


@dataclass(frozen=True)
class Prediction:
    flagged: bool
    findings: frozenset[str]
    decisions: frozenset[str]
    evidence: frozenset[str]
    score: float | None = None


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def opaque_target_id(source_id: str) -> str:
    digest = hashlib.sha256(TARGET_ID_DOMAIN + source_id.encode("utf-8")).hexdigest()
    return f"target-{digest[:24]}"


def _string_tuple(value: object, *, field: str, source_id: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"{source_id}: {field} must be a list of non-empty strings")
    if len(set(value)) != len(value):
        raise ValueError(f"{source_id}: {field} contains duplicate values")
    return tuple(value)


def load_targets() -> list[Target]:
    targets: list[Target] = []
    for path in sorted(CORPUS.glob("*.json")):
        case = json.loads(path.read_text(encoding="utf-8"))
        source_id = f"corpus/{case['id']}"
        expected = case["expected"]
        targets.append(Target(
            source_id=source_id,
            target_id=opaque_target_id(source_id),
            suite="corpus",
            category=case["category"],
            input=case["input"],
            expected_flagged=not case["benign"],
            expected_findings=_string_tuple(expected.get("findings", []), field="expected.findings", source_id=source_id),
            expected_decisions=_string_tuple(expected.get("decisions", []), field="expected.decisions", source_id=source_id),
            minimum_evidence=_string_tuple(expected.get("minimum_evidence", []), field="expected.minimum_evidence", source_id=source_id),
        ))

    pair_doc = json.loads(DRIFT_PAIRS.read_text(encoding="utf-8"))
    if pair_doc.get("schema_version") != "2":
        raise ValueError("drift_pairs.json schema_version must be 2")
    for item in pair_doc["pairs"]:
        expected = item["expected"]
        minimum_evidence = _string_tuple(expected.get("minimum_evidence", []), field="expected.minimum_evidence", source_id=item["id"])
        decisions = _string_tuple(expected.get("decisions", []), field="expected.decisions", source_id=item["id"])
        finding = expected.get("finding")
        if not isinstance(finding, str) or not finding:
            raise ValueError(f"{item['id']}: expected.finding must be non-empty")
        for side, flagged in (("baseline", False), ("mutated", True)):
            if expected[f"{side}_flagged"] is not flagged:
                raise ValueError(f"{item['id']}: invalid {side}_flagged")
            source_id = f"pair/{item['id']}/{side}"
            targets.append(Target(
                source_id=source_id,
                target_id=opaque_target_id(source_id),
                suite="pair",
                category=item["drift_class"],
                input=item[f"{side}_input"],
                expected_flagged=flagged,
                expected_findings=(finding,) if flagged else (),
                expected_decisions=decisions if flagged else (),
                minimum_evidence=minimum_evidence if flagged else (),
                drift_class=item["drift_class"],
                attack_type=item["attack_type"],
                split=item["split"],
                pair_id=item["id"],
                pair_side=side,
                ground_truth_reason=expected.get("ground_truth_reason"),
            ))

    controls_doc = json.loads(HARD_CONTROLS.read_text(encoding="utf-8"))
    for item in controls_doc["controls"]:
        expected = item["expected"]
        source_id = f"control/{item['id']}"
        targets.append(Target(
            source_id=source_id,
            target_id=opaque_target_id(source_id),
            suite="control",
            category=item["drift_class"],
            input=item["input"],
            expected_flagged=False,
            expected_findings=(),
            expected_decisions=(),
            minimum_evidence=(),
            drift_class=item["drift_class"],
            attack_type=item["attack_type"],
            split=item["split"],
            ground_truth_reason=expected.get("ground_truth_reason"),
        ))
    ids = [target.target_id for target in targets]
    if len(ids) != len(set(ids)):
        raise ValueError("opaque target ID collision")
    return targets


def select_targets(targets: list[Target], focus: str, split: str) -> list[Target]:
    if focus == "corpus":
        selected = [target for target in targets if target.suite == "corpus"]
    elif focus == "drift":
        selected = [target for target in targets if target.suite in {"pair", "control"}]
    else:
        selected = list(targets)
    if split != "all":
        selected = [target for target in selected if target.split == split]
    if not selected:
        raise ValueError(f"no targets selected for focus={focus} split={split}")
    return selected


def ratio(n: int, d: int) -> float | None:
    return n / d if d else None


def wilson_interval(successes: int, total: int, z: float = 1.959963984540054) -> list[float] | None:
    if total <= 0:
        return None
    p = successes / total
    z2 = z * z
    denominator = 1.0 + z2 / total
    center = (p + z2 / (2.0 * total)) / denominator
    half = z * math.sqrt((p * (1.0 - p) + z2 / (4.0 * total)) / total) / denominator
    return [max(0.0, center - half), min(1.0, center + half)]


def classification_metrics(targets: list[Target], predictions: dict[str, Prediction]) -> dict:
    tp = tn = fp = fn = 0
    for target in targets:
        predicted = predictions[target.target_id].flagged
        if target.expected_flagged and predicted:
            tp += 1
        elif target.expected_flagged:
            fn += 1
        elif predicted:
            fp += 1
        else:
            tn += 1
    positives = tp + fn
    negatives = tn + fp
    precision = ratio(tp, tp + fp)
    recall = ratio(tp, positives)
    specificity = ratio(tn, negatives)
    fpr = ratio(fp, negatives)
    fnr = ratio(fn, positives)
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
    balanced = (recall + specificity) / 2 if recall is not None and specificity is not None else None
    return {
        "targets": len(targets),
        "confusion": {"tp": tp, "tn": tn, "fp": fp, "fn": fn},
        "tpr_recall": recall,
        "fnr": fnr,
        "fnr_95ci_wilson": wilson_interval(fn, positives),
        "fpr": fpr,
        "fpr_95ci_wilson": wilson_interval(fp, negatives),
        "specificity": specificity,
        "precision": precision,
        "f1": f1,
        "balanced_accuracy": balanced,
    }


def set_metrics(targets: list[Target], predictions: dict[str, Prediction], *, expected_attr: str, predicted_attr: str, only_when_expected: bool = False) -> dict:
    exact = overlap = expected_total = predicted_total = evaluated = 0
    for target in targets:
        expected = set(getattr(target, expected_attr))
        if only_when_expected and not expected:
            continue
        predicted = set(getattr(predictions[target.target_id], predicted_attr))
        evaluated += 1
        exact += int(predicted == expected)
        overlap += len(expected & predicted)
        expected_total += len(expected)
        predicted_total += len(predicted)
    precision = ratio(overlap, predicted_total)
    recall = ratio(overlap, expected_total)
    f1 = 2 * precision * recall / (precision + recall) if precision is not None and recall is not None and precision + recall else None
    return {
        "targets": evaluated,
        "exact_match_rate": ratio(exact, evaluated),
        "micro_precision": precision,
        "micro_recall": recall,
        "micro_f1": f1,
        "expected_items": expected_total,
        "predicted_items": predicted_total,
        "matched_items": overlap,
    }


def evidence_metrics(targets: list[Target], predictions: dict[str, Prediction]) -> dict:
    complete = matched = expected_total = evaluated = 0
    for target in targets:
        expected = set(target.minimum_evidence)
        if not expected:
            continue
        predicted = set(predictions[target.target_id].evidence)
        evaluated += 1
        complete += int(expected <= predicted)
        matched += len(expected & predicted)
        expected_total += len(expected)
    return {
        "targets": evaluated,
        "target_complete_rate": ratio(complete, evaluated),
        "required_item_recall": ratio(matched, expected_total),
        "required_items": expected_total,
        "matched_required_items": matched,
    }


def target_semantically_complete(target: Target, prediction: Prediction) -> bool:
    if prediction.flagged is not target.expected_flagged:
        return False
    if set(prediction.findings) != set(target.expected_findings):
        return False
    if target.expected_decisions and set(prediction.decisions) != set(target.expected_decisions):
        return False
    if target.minimum_evidence and not set(target.minimum_evidence) <= set(prediction.evidence):
        return False
    return True


def semantic_metrics(targets: list[Target], predictions: dict[str, Prediction]) -> dict:
    complete = sum(int(target_semantically_complete(target, predictions[target.target_id])) for target in targets)
    return {"targets": len(targets), "complete": complete, "complete_rate": ratio(complete, len(targets))}


def pair_metrics(targets: list[Target], predictions: dict[str, Prediction]) -> dict:
    pairs: dict[str, dict[str, Target]] = {}
    for target in targets:
        if target.suite == "pair" and target.pair_id and target.pair_side:
            pairs.setdefault(target.pair_id, {})[target.pair_side] = target
    correct = baseline_fp = mutated_tp = changed = semantic_complete = 0
    for pair_id, sides in pairs.items():
        if set(sides) != {"baseline", "mutated"}:
            raise ValueError(f"{pair_id}: incomplete pair")
        baseline_target = sides["baseline"]
        mutated_target = sides["mutated"]
        baseline = predictions[baseline_target.target_id]
        mutated = predictions[mutated_target.target_id]
        baseline_fp += int(baseline.flagged)
        mutated_tp += int(mutated.flagged)
        changed += int(baseline.flagged != mutated.flagged)
        pair_correct = (not baseline.flagged) and mutated.flagged
        correct += int(pair_correct)
        semantic_complete += int(pair_correct and target_semantically_complete(baseline_target, baseline) and target_semantically_complete(mutated_target, mutated))
    total = len(pairs)
    mutated_fnr = ratio(total - mutated_tp, total)
    return {
        "pairs": total,
        "fully_correct_pairs": correct,
        "pair_accuracy": ratio(correct, total),
        "baseline_false_positive_rate": ratio(baseline_fp, total),
        "mutated_true_positive_rate": ratio(mutated_tp, total),
        "mutated_false_negative_rate": mutated_fnr,
        "prediction_changed_rate": ratio(changed, total),
        "correct_direction_given_change": ratio(correct, changed),
        "semantic_pair_accuracy": ratio(semantic_complete, total),
    }


def raw_score_metrics(targets: list[Target], predictions: dict[str, Prediction]) -> dict:
    rows = [(target, predictions[target.target_id].score) for target in targets]
    provided = [(target, score) for target, score in rows if score is not None]
    positives = [float(score) for target, score in provided if target.expected_flagged]
    negatives = [float(score) for target, score in provided if not target.expected_flagged]
    auc = None
    if positives and negatives and len(provided) == len(rows):
        wins = 0.0
        for pos in positives:
            for neg in negatives:
                wins += 1.0 if pos > neg else 0.5 if pos == neg else 0.0
        auc = wins / (len(positives) * len(negatives))
    return {
        "provided": len(provided),
        "targets": len(rows),
        "coverage": ratio(len(provided), len(rows)),
        "positive_mean": sum(positives) / len(positives) if positives else None,
        "negative_mean": sum(negatives) / len(negatives) if negatives else None,
        "roc_auc": auc,
    }


def coverage_matrix_summary(targets: list[Target]) -> dict:
    drift_targets = [target for target in targets if target.drift_class]
    classes = sorted({target.drift_class for target in drift_targets if target.drift_class})
    by_class = {}
    for drift_class in classes:
        subset = [target for target in drift_targets if target.drift_class == drift_class]
        by_class[drift_class] = {
            "targets": len(subset),
            "positives": sum(target.expected_flagged for target in subset),
            "negatives": sum(not target.expected_flagged for target in subset),
            "attack_types": sorted({target.attack_type for target in subset if target.attack_type}),
            "splits": sorted({target.split for target in subset}),
            "expected_decisions": sorted({decision for target in subset for decision in target.expected_decisions} | ({"pass"} if any(not target.expected_flagged for target in subset) else set())),
        }
    return {"drift_classes": len(classes), "by_class": by_class}


def _prediction_set(row: dict, key: str, line_no: int) -> frozenset[str]:
    value = row.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ValueError(f"line {line_no}: {key} must be a list of non-empty strings")
    if len(set(value)) != len(value):
        raise ValueError(f"line {line_no}: {key} contains duplicate values")
    return frozenset(value)


def read_predictions(path: Path) -> dict[str, Prediction]:
    predictions: dict[str, Prediction] = {}
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not raw.strip():
            continue
        row = json.loads(raw)
        if not isinstance(row, dict):
            raise ValueError(f"line {line_no}: prediction must be a JSON object")
        target_id, flagged = row.get("target_id"), row.get("flagged")
        if not isinstance(target_id, str) or not isinstance(flagged, bool):
            raise ValueError(f"line {line_no}: expected target_id:string and flagged:boolean")
        if target_id in predictions:
            raise ValueError(f"line {line_no}: duplicate target_id {target_id}")
        raw_score = row.get("score")
        if raw_score is not None and (not isinstance(raw_score, (int, float)) or isinstance(raw_score, bool) or not 0.0 <= float(raw_score) <= 1.0):
            raise ValueError(f"line {line_no}: score must be a number in [0,1]")
        predictions[target_id] = Prediction(
            flagged=flagged,
            findings=_prediction_set(row, "findings", line_no),
            decisions=_prediction_set(row, "decisions", line_no),
            evidence=_prediction_set(row, "evidence", line_no),
            score=float(raw_score) if raw_score is not None else None,
        )
    return predictions


def public_input(target: Target) -> object:
    value = json.loads(json.dumps(target.input, ensure_ascii=False))
    if isinstance(value, dict):
        value.pop("variant", None)
        artifact = value.get("artifact")
        if isinstance(artifact, dict):
            if "name" in artifact:
                artifact["name"] = f"artifact-{target.target_id.removeprefix('target-')[:8]}"
            if artifact.get("source") in {"local", "synthetic"}:
                artifact["source"] = "local"
    return value


def public_records(targets: list[Target]) -> list[dict]:
    return [{"target_id": target.target_id, "input": public_input(target)} for target in sorted(targets, key=lambda item: item.target_id)]


def target_set_digest(targets: list[Target]) -> str:
    return hashlib.sha256(canonical_bytes(public_records(targets))).hexdigest()


def score(targets: list[Target], predictions: dict[str, Prediction]) -> dict:
    expected_ids = {target.target_id for target in targets}
    missing = sorted(expected_ids - predictions.keys())
    unknown = sorted(predictions.keys() - expected_ids)
    if missing:
        raise ValueError(f"missing {len(missing)} predictions; first={missing[0]}")
    if unknown:
        raise ValueError(f"unknown {len(unknown)} predictions; first={unknown[0]}")
    corpus = [target for target in targets if target.suite == "corpus"]
    pair_targets = [target for target in targets if target.suite == "pair"]
    controls = [target for target in targets if target.suite == "control"]
    per_drift_class = {
        drift_class: classification_metrics([target for target in targets if target.drift_class == drift_class], predictions)
        for drift_class in sorted({target.drift_class for target in targets if target.drift_class})
    }
    return {
        "schema_version": "3",
        "benchmark": "proofdrift_detector_quality",
        "benchmark_version": BENCHMARK_VERSION,
        "target_set_digest": target_set_digest(targets),
        "coverage": {"predicted": len(predictions), "expected": len(targets), "ratio": ratio(len(predictions), len(targets))},
        "overall": classification_metrics(targets, predictions),
        "corpus": classification_metrics(corpus, predictions) if corpus else None,
        "pair_targets": classification_metrics(pair_targets, predictions) if pair_targets else None,
        "hard_controls": classification_metrics(controls, predictions) if controls else None,
        "findings": set_metrics(targets, predictions, expected_attr="expected_findings", predicted_attr="findings"),
        "decisions": set_metrics(targets, predictions, expected_attr="expected_decisions", predicted_attr="decisions", only_when_expected=True),
        "evidence": evidence_metrics(targets, predictions),
        "semantic": semantic_metrics(targets, predictions),
        "drift_pairs": pair_metrics(targets, predictions) if pair_targets else None,
        "per_drift_class_binary": per_drift_class,
        "coverage_matrix": coverage_matrix_summary(targets),
        "raw_scores": raw_score_metrics(targets, predictions),
        "note": "Metrics score supplied predictions. emit hides labels, drift class, attack type, split, pair membership, and ground-truth rationale.",
    }


def emit(targets: list[Target]) -> None:
    for record in public_records(targets):
        print(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def ground_truth_predictions(targets: list[Target]) -> dict[str, Prediction]:
    return {
        target.target_id: Prediction(
            flagged=target.expected_flagged,
            findings=frozenset(target.expected_findings),
            decisions=frozenset(target.expected_decisions),
            evidence=frozenset(target.minimum_evidence),
            score=1.0 if target.expected_flagged else 0.0,
        )
        for target in targets
    }


def self_test(targets: list[Target]) -> dict:
    records = public_records(targets)
    assert all(set(record) == {"target_id", "input"} for record in records)
    forbidden = ("benign", "baseline", "mutated", "corpus", "pair", "control", "provenance", "capability", "policy", "runtime")
    assert all(not any(token in record["target_id"].lower() for token in forbidden) for record in records)
    result = score(targets, ground_truth_predictions(targets))
    assert result["overall"]["fpr"] == 0.0
    assert result["overall"]["fnr"] == 0.0
    assert result["raw_scores"]["roc_auc"] == 1.0
    if result["drift_pairs"]:
        assert result["drift_pairs"]["pair_accuracy"] == 1.0
        assert result["drift_pairs"]["mutated_false_negative_rate"] == 0.0
    positives = [target for target in targets if target.expected_flagged]
    negatives = [target for target in targets if not target.expected_flagged]
    if positives and negatives:
        perturbed = ground_truth_predictions(targets)
        pos = positives[0]
        neg = negatives[0]
        perturbed[pos.target_id] = Prediction(False, frozenset(), frozenset(), frozenset(), 0.0)
        perturbed[neg.target_id] = Prediction(True, frozenset(), frozenset(), frozenset(), 1.0)
        perturbed_result = score(targets, perturbed)
        assert perturbed_result["overall"]["fpr"] > 0.0
        assert perturbed_result["overall"]["fnr"] > 0.0
    return result


def below(value: float | None, minimum: float | None) -> bool:
    return minimum is not None and (value is None or value < minimum)


def above(value: float | None, maximum: float | None) -> bool:
    return maximum is not None and (value is None or value > maximum)


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("emit", "self-test"):
        p = sub.add_parser(name)
        p.add_argument("--focus", choices=("all", "corpus", "drift"), default="all")
        p.add_argument("--split", choices=("all", "train", "dev", "test"), default="all")
    score_parser = sub.add_parser("score")
    score_parser.add_argument("predictions", type=Path)
    score_parser.add_argument("--focus", choices=("all", "corpus", "drift"), default="all")
    score_parser.add_argument("--split", choices=("all", "train", "dev", "test"), default="all")
    score_parser.add_argument("--max-fpr", type=float)
    score_parser.add_argument("--max-fnr", type=float)
    score_parser.add_argument("--min-pair-accuracy", type=float)
    score_parser.add_argument("--max-pair-baseline-fpr", type=float)
    score_parser.add_argument("--max-pair-fnr", type=float)
    score_parser.add_argument("--min-finding-f1", type=float)
    score_parser.add_argument("--min-decision-accuracy", type=float)
    score_parser.add_argument("--min-evidence-completeness", type=float)
    score_parser.add_argument("--min-semantic-complete", type=float)
    args = parser.parse_args()

    targets = select_targets(load_targets(), args.focus, args.split)
    if args.command == "emit":
        emit(targets)
        return 0
    if args.command == "self-test":
        print(json.dumps(self_test(targets), indent=2, sort_keys=True))
        return 0

    result = score(targets, read_predictions(args.predictions))
    print(json.dumps(result, indent=2, sort_keys=True))
    failed = above(result["overall"]["fpr"], args.max_fpr)
    failed = failed or above(result["overall"]["fnr"], args.max_fnr)
    pairs = result["drift_pairs"]
    if pairs:
        failed = failed or below(pairs["pair_accuracy"], args.min_pair_accuracy)
        failed = failed or above(pairs["baseline_false_positive_rate"], args.max_pair_baseline_fpr)
        failed = failed or above(pairs["mutated_false_negative_rate"], args.max_pair_fnr)
    failed = failed or below(result["findings"]["micro_f1"], args.min_finding_f1)
    failed = failed or below(result["decisions"]["exact_match_rate"], args.min_decision_accuracy)
    failed = failed or below(result["evidence"]["target_complete_rate"], args.min_evidence_completeness)
    failed = failed or below(result["semantic"]["complete_rate"], args.min_semantic_complete)
    return 2 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
