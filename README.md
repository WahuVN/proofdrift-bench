# ProofDrift Bench

**English** | [Tiếng Việt](README.vi.md)

[![Benchmark CI](https://github.com/WahuVN/proofdrift-bench/actions/workflows/ci.yml/badge.svg)](https://github.com/WahuVN/proofdrift-bench/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Evidence-first adversarial corpus and implementation-neutral benchmark harness for ProofDrift-style coding-agent change control.

The benchmark is deliberately separate from the production implementation. It measures whether a detector distinguishes security-relevant drift from near-identical safe inputs and whether that detector does so without unacceptable false positives or false negatives.

## Benchmark v3

The repository keeps the existing **160-case legacy security corpus** (146 adversarial, 14 benign, 52 categories) and adds a deterministic drift-science suite with **66 targets**:

- **24 minimal safe-to-risky drift pairs**: 48 pair targets.
- **18 hard-negative controls**: reordered fields, irrelevant noise, and benign strengthening.
- Exactly **24 positive** and **42 negative** drift-science targets.
- Deterministic generation seed: `20260911`.

The six canonical drift classes are represented in machine-readable files as:

| Canonical class | Machine name |
| --- | --- |
| provenance drift | `provenance_drift` |
| capability drift | `capability_drift` |
| policy drift | `policy_drift` |
| runtime drift | `runtime_drift` |
| patch-impact drift | `patch_impact_drift` |
| test-proof drift | `test_proof_drift` |

Each class has exactly four positive minimal pairs and three extra hard-negative controls. Every class covers `train`, `dev`, and `test` splits and includes `pass`, `warn`, and `block` outcomes in the coverage matrix.

The suite includes the required adversarial dimensions: reordered fields, irrelevant noise, stale evidence, forged provenance, missing references, conflicting policy, capability escalation, replay, and partial test proof. Additional pair types cover scope escalation, policy downgrade, request binding, TOCTOU command swaps, patch-scope escape, dependency-policy changes, stale test proof, and missing execution receipts.

## Files that define benchmark v3

- `generate_science_suite.py` is the deterministic source for generated drift fixtures and manifests.
- `drift_pairs.json` contains 24 minimal pairs with exact JSON-pointer `changed_paths` and ground-truth rationale.
- `hard_controls.json` contains 18 negative controls.
- `coverage_matrix.json` maps class × attack type × split × expected decision.
- `benchmark_manifest.json` records version, seed, counts, class/split balance, and corpus digests.
- `evaluate_quality.py` emits label-free targets and scores detector predictions.
- `benchmark_thresholds.json` stores the committed FPR/FNR and pair-quality gates.
- `benchmark_baseline.json` pins the drift target-set digest and harness baseline.
- `verify_quality_gate.py` verifies corpus/scorer integrity and proves the thresholds catch a deliberate regression.
- `BENCHMARK_METHODOLOGY.md` documents the benchmark protocol and interpretation rules.

## Validate the benchmark

```sh
python -m py_compile generate_science_suite.py evaluate_quality.py verify_quality_gate.py verify_corpus.py run_benchmark.py
python generate_science_suite.py --check
python verify_corpus.py
python evaluate_quality.py self-test --focus drift
python verify_quality_gate.py
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

`generate_science_suite.py --check` fails if a generated benchmark file no longer matches the deterministic source. `verify_corpus.py` independently checks pair deltas, class/split balance, required attack coverage, hard negatives, coverage matrix, manifest digests, and the legacy security invariants.

## Run an external detector

Export only detector-visible inputs:

```sh
python evaluate_quality.py emit --focus drift > targets.jsonl
```

Each emitted line contains only:

```json
{"target_id":"target-...","input":{}}
```

The emitted stream intentionally omits labels, class, attack type, split, pair membership, pair side, and ground-truth rationale. This prevents the scoring metadata itself from trivially revealing the answer.

Run a detector over `targets.jsonl` and write one prediction for every target:

```json
{"target_id":"target-...","flagged":true,"score":0.93,"findings":[],"decisions":[],"evidence":[]}
```

Only `target_id` and `flagged` are mandatory. `score` is optional and must be in `[0,1]`; when every target supplies a score, the scorer also reports ROC AUC. `findings`, `decisions`, and `evidence` enable the semantic-quality metrics.

Score the predictions:

```sh
python evaluate_quality.py score predictions.jsonl --focus drift
```

Apply the committed release gate:

```sh
python verify_quality_gate.py predictions.jsonl
```

The committed v3 binary/pair thresholds are:

- overall FPR ≤ 5%
- overall FNR ≤ 5%
- minimal-pair accuracy ≥ 90%
- pair-baseline FPR ≤ 5%
- mutated-pair FNR ≤ 5%

The command exits with status `2` when any gate is violated, so it can be used directly in CI for a detector integration.

## Metrics

For supplied detector predictions, the scorer reports:

- confusion counts: TP, FP, TN, FN
- precision, recall/TPR, specificity, F1, balanced accuracy
- **FPR = FP / (FP + TN)**
- **FNR = FN / (FN + TP)**
- Wilson 95% intervals for FPR and FNR
- minimal-pair accuracy
- pair-baseline FPR
- mutated-side TPR and FNR
- prediction-changed rate and correct-direction-given-change
- finding/decision/evidence quality
- semantic-complete rate
- optional raw-score coverage, positive/negative means, and ROC AUC
- per-drift-class binary metrics and a class/attack/split/decision coverage summary

A low FNR alone is not sufficient: a detector that flags everything will have catastrophic FPR. A low FPR alone is also insufficient: a detector that flags nothing will have catastrophic FNR. The minimal-pair metrics force both sides of the same near-identical change to be handled correctly.

## Splits and label leakage

The generated suite uses deterministic `train`, `dev`, and `test` assignments. Split metadata is hidden from the `emit` stream and can be selected explicitly by the scorer, for example:

```sh
python evaluate_quality.py emit --focus drift --split test > test-targets.jsonl
python evaluate_quality.py score test-predictions.jsonl --focus drift --split test
```

Because this repository is public, these splits are **reproducible evaluation partitions, not a secret holdout**. A hosted/private evaluation can use the same format with unreleased cases for a genuinely hidden test set.

## Ground truth and reproducibility

Every positive pair changes only the declared JSON-pointer paths. The safe baseline is labeled negative, the mutated side is labeled positive, and each pair carries a human-readable rationale plus required evidence fields. Hard-negative controls are explicitly labeled safe despite harmless reordering/noise/strengthening.

`benchmark_manifest.json` pins the deterministic seed and suite digest. `benchmark_baseline.json` additionally pins the opaque drift target-set digest. Changing fixtures or labels therefore requires an intentional baseline update rather than silently moving the measurement target.

`evaluate_quality.py self-test` uses benchmark ground truth to test the **scorer itself**. Its perfect scores are not a detector-performance result. `verify_quality_gate.py` likewise uses the ground-truth oracle only to test harness integrity and then deliberately injects false positives/false negatives to prove the gate rejects a regression.

## Legacy reference benchmark

```sh
python run_benchmark.py
```

This measures canonical legacy-corpus digest throughput only. It is not an end-to-end ProofDrift policy, broker, scanner, detector, or runtime performance claim. `benchmark_result_reference.json` records the environment that produced the committed reference result.

## Fuzz seeds

`seeds/` contains deterministic synthetic inputs for parser, path, secret, approval, MCP, archive, and evidence fuzzing. They contain no real credentials.

The implementation lives in [WahuVN/proofdrift](https://github.com/WahuVN/proofdrift). Public wire contracts live in [WahuVN/proofdrift-spec](https://github.com/WahuVN/proofdrift-spec).

## License

Apache License 2.0. See [LICENSE](LICENSE).
