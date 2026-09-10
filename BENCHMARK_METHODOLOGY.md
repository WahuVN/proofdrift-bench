# ProofDrift Bench v3 Methodology

## Goal

ProofDrift Bench v3 measures whether a change-control detector can distinguish a security-relevant drift from a nearby safe state without solving the task by fixture-name, label, category, or pair-side leakage.

The primary scientific unit is a **minimal drift pair**: a safe baseline and a risky mutation with an explicitly enumerated JSON-pointer delta. Hard-negative controls test invariance to changes that should not trigger a security finding.

This repository is implementation-neutral. It does not assume that the detector is the ProofDrift reference implementation.

## Canonical drift classes

The benchmark preserves the six requested concepts exactly; JSON uses snake_case only as a serialization convention:

1. provenance drift → `provenance_drift`
2. capability drift → `capability_drift`
3. policy drift → `policy_drift`
4. runtime drift → `runtime_drift`
5. patch-impact drift → `patch_impact_drift`
6. test-proof drift → `test_proof_drift`

Every class has four minimal positive pairs and three additional hard-negative controls. This produces equal class weight: 11 scored targets per class.

## Suite construction

`generate_science_suite.py` is the source of truth for the v3 drift-science fixtures. Generation uses seed `20260911` to produce a stable order and emits four generated artifacts:

- `drift_pairs.json`
- `hard_controls.json`
- `coverage_matrix.json`
- `benchmark_manifest.json`

`python generate_science_suite.py --check` compares those committed files with a fresh in-memory generation and exits non-zero if they diverge.

### Minimal pairs

Each pair contains:

- stable pair ID
- canonical drift class
- attack type
- train/dev/test split
- safe `baseline_input`
- risky `mutated_input`
- exact `changed_paths`
- expected safe/risky labels
- expected finding
- expected `warn` or `block` decision
- minimum evidence requirements
- human-readable ground-truth rationale

`verify_corpus.py` independently computes the recursive JSON diff and requires it to exactly match `changed_paths`. This prevents accidental hidden mutations from turning a supposed minimal pair into a multi-variable example.

### Hard negatives

Each class has three negative controls:

- `reordered_fields`: semantically identical content with field order changed
- `irrelevant_noise`: safe input plus unrelated metadata
- `benign_strengthening`: safe input plus an assurance-only strengthening field

Pair baselines are also negatives. Therefore each class has four risky mutated targets and seven negative targets: four safe pair baselines plus three hard controls.

### Required adversarial dimensions

The generated suite explicitly includes:

- reordered fields
- irrelevant noise
- stale evidence
- forged provenance
- missing references
- conflicting policy
- capability escalation
- replay
- partial test proof

Additional attacks increase coverage of scope escalation, network-method escalation, policy downgrade, request binding mismatch, TOCTOU command replacement, patch scope escape, dependency-policy changes, generated-to-runtime source changes, stale test proof, and missing execution receipts.

## Dataset counts

The v3 drift-science suite contains:

- 24 minimal pairs
- 48 pair targets
- 18 hard-negative controls
- 66 total drift-science targets
- 24 positives
- 42 negatives
- 6 drift classes
- 11 targets per drift class

The older 160-case security corpus remains available separately and is included when `--focus all` is selected.

## Splits

Pair-level split assignment is deterministic so the two sides of a pair never land in different partitions.

For pairs:

- train: 6 pairs
- dev: 6 pairs
- test: 12 pairs

For additional hard controls:

- train: 6 controls
- dev: 6 controls
- test: 6 controls

Use `--split train`, `--split dev`, or `--split test` with both `emit` and `score`.

Because the repository itself is public, the committed test partition is not claimed to be secret. It is a reproducible evaluation partition. A service that needs a true hidden test can reuse the same target/prediction format with unreleased cases.

## Anti-leak evaluation protocol

The public detector stream is produced by:

```sh
python evaluate_quality.py emit --focus drift
```

It exposes only an opaque target ID and the detector input. It does **not** expose:

- expected label
- drift class
- attack type
- split
- pair ID
- baseline/mutated side
- ground-truth rationale

Opaque IDs are derived in a benchmark-version domain and do not contain semantic label tokens.

The scorer keeps the label-bearing metadata internally. A detector is expected to produce exactly one prediction for every emitted target. Missing IDs, duplicate IDs, and unknown IDs are rejected.

## Prediction contract

Minimum prediction:

```json
{"target_id":"target-...","flagged":true}
```

Extended prediction:

```json
{
  "target_id": "target-...",
  "flagged": true,
  "score": 0.93,
  "findings": ["critical:EXAMPLE"],
  "decisions": ["block"],
  "evidence": ["example_receipt"]
}
```

`score` is optional but, when present, must be in `[0,1]`. ROC AUC is reported only when every selected target supplies a score.

## Binary metrics

For every selected target the scorer computes TP, TN, FP, and FN. It derives:

- TPR / recall = TP / (TP + FN)
- FNR = FN / (FN + TP)
- FPR = FP / (FP + TN)
- specificity = TN / (TN + FP)
- precision = TP / (TP + FP)
- F1
- balanced accuracy

FPR and FNR also include 95% Wilson intervals. Intervals are important because the drift-science suite is intentionally small enough to remain reviewable; a point estimate of zero is not evidence that the population error rate is literally zero.

## Minimal-pair metrics

For each pair, correctness requires both of these simultaneously:

1. baseline is not flagged
2. mutated side is flagged

The scorer reports:

- pair accuracy
- pair-baseline FPR
- mutated-side TPR
- mutated-side FNR
- prediction-changed rate
- correct direction given a changed prediction
- semantic pair accuracy

Pair accuracy prevents a detector from receiving full credit for detecting the risky side while also flagging its near-identical safe baseline.

## Semantic metrics

When a detector emits findings, decisions, and evidence, the scorer also measures:

- finding exact match and micro precision/recall/F1
- decision exact match
- required-evidence target completeness and item recall
- whole-target semantic completeness

These metrics are reported separately from binary FPR/FNR so a consumer can distinguish “detected something risky” from “detected the expected risk with sufficient proof.”

## Coverage matrix

`coverage_matrix.json` makes the test design auditable. Rows map:

`drift class × attack type × split × hardness × expected decision`

Every drift class has:

- 4 hard-positive rows
- 7 hard-negative rows
- train/dev/test coverage
- pass/warn/block outcome coverage

`verify_corpus.py` enforces those counts and outcome dimensions.

## Reproducibility and integrity

`benchmark_manifest.json` records:

- benchmark version
- deterministic seed
- suite file names
- per-class counts
- split counts
- legacy corpus digest
- drift suite digest

`benchmark_baseline.json` pins the opaque detector target-set digest in addition to counts and perfect harness-oracle metrics. A fixture/label change therefore requires an explicit baseline update.

The baseline is deliberately described as a **harness baseline**, not a detector result. A ground-truth oracle is appropriate for verifying scoring code, but it is invalid evidence of detector performance.

## Quality gate

`benchmark_thresholds.json` defines the v3 binary/pair release thresholds:

- max FPR: 0.05
- max FNR: 0.05
- min pair accuracy: 0.90
- max pair-baseline FPR: 0.05
- max mutated-pair FNR: 0.05

For real predictions:

```sh
python verify_quality_gate.py predictions.jsonl
```

The command exits `2` when any threshold fails.

Without a predictions file, `verify_quality_gate.py` is a regression test for the benchmark machinery itself. It first verifies the pinned harness baseline, then intentionally flips three pair baselines to false positives and two mutated sides to false negatives. The test succeeds only if all five gate dimensions detect the injected regression.

This design checks both directions of the release gate. A CI job cannot pass merely because threshold configuration exists but is unused.

## CI protocol

The benchmark CI runs, in order:

```sh
python -m py_compile generate_science_suite.py evaluate_quality.py verify_quality_gate.py verify_corpus.py run_benchmark.py
python generate_science_suite.py --check
python verify_corpus.py
python evaluate_quality.py self-test --focus drift
python verify_quality_gate.py
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
python run_benchmark.py
```

The Python stages are sufficient to validate the v3 drift science and quality-gate logic. Rust stages retain the existing property/regression coverage for benchmark utility code.

## Interpretation limits

A benchmark result applies to the exact target-set digest and detector configuration that produced it. Do not claim that the harness self-test is detector performance. Do not compare results from different target-set digests as though they are the same experiment. Do not treat a public split as a secret holdout.

The committed corpus is synthetic and deterministic. It is designed for reproducible adversarial regression, not as a substitute for production telemetry, real-world incident review, or an independently hidden evaluation set.
