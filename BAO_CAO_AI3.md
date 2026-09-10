# BÁO CÁO AI 3 — proofdrift-bench

Branch: `ai3-bench-science`

## Summary

AI 3 đã nâng `proofdrift-bench` từ corpus adversarial tổng quát + drift-pair thử nghiệm thành benchmark drift-science v3 có cấu trúc, tái lập được và có release gate FPR/FNR thực sự.

Kết quả chính:

- Giữ nguyên legacy corpus: 160 case, 52 category, 146 adversarial, 14 benign.
- Tạo 24 minimal drift pair cân bằng tuyệt đối theo 6 canonical drift class: 4 pair/class.
- Tạo 18 hard-negative control: 3 control/class.
- Tổng drift-science: 66 target = 24 positive + 42 negative.
- Có deterministic seed `20260911`, manifest, corpus digest, suite digest và opaque target-set digest.
- Có split train/dev/test ở cấp pair; baseline và mutated side luôn cùng split.
- `emit` không lộ label, drift class, attack type, split, pair membership, pair side hoặc ground-truth rationale.
- Scorer báo TP/FP/TN/FN, precision, recall/TPR, FPR, FNR, Wilson 95% CI, F1, balanced accuracy, pair metrics, semantic metrics, per-class metrics và optional raw score / ROC AUC.
- Có quality gate commit cố định cho FPR/FNR + minimal-pair quality.
- Có regression test chủ động bơm FP/FN để chứng minh gate thật sự fail khi vượt ngưỡng.
- CI đã được nối deterministic-generation check + corpus invariants + scorer self-test + FPR/FNR regression gate trước Rust lint/test.

Canonical concepts không bị đổi nghĩa. Machine-readable JSON dùng snake_case tương ứng:

- provenance drift → `provenance_drift`
- capability drift → `capability_drift`
- policy drift → `policy_drift`
- runtime drift → `runtime_drift`
- patch-impact drift → `patch_impact_drift`
- test-proof drift → `test_proof_drift`

## Files changed

### New

- `generate_science_suite.py`
  - deterministic source of truth cho drift suite v3
  - seed `20260911`
  - sinh pair, hard controls, coverage matrix, manifest
  - `--check` fail nếu generated artifacts stale
- `drift_pairs.json`
  - schema v2
  - 24 minimal pair, 4/class
  - exact JSON-pointer changed paths
  - finding/decision/minimum evidence/ground-truth rationale
- `hard_controls.json`
  - 18 hard negative, 3/class
  - reordered fields / irrelevant noise / benign strengthening
- `coverage_matrix.json`
  - class × attack type × split × hardness × expected decision
  - 66 rows
- `benchmark_manifest.json`
  - benchmark version, deterministic seed, counts, class/split distribution, digests
- `benchmark_thresholds.json`
  - max FPR 0.05
  - max FNR 0.05
  - min pair accuracy 0.90
  - max pair-baseline FPR 0.05
  - max mutated-pair FNR 0.05
- `benchmark_baseline.json`
  - pins drift target-set digest
  - pins counts + harness-oracle baseline
  - explicitly not a detector-performance claim
- `verify_quality_gate.py`
  - validates pinned baseline + thresholds
  - optional real-predictions gate
  - deliberate FP/FN regression injection test
- `BENCHMARK_METHODOLOGY.md`
  - full protocol, metrics, split/anti-leak/reproducibility/interpretation rules
- `BAO_CAO_AI3.md`
  - final AI3 handoff report

### Modified

- `evaluate_quality.py`
  - benchmark/scorer schema v3
  - drift class + attack + split metadata internal only
  - explicit FNR + Wilson CI
  - raw score + ROC AUC
  - hard controls
  - per-drift-class binary metrics
  - coverage summary
  - train/dev/test selection
  - pair mutated FNR
  - anti-leak and metric perturbation self-tests
- `verify_corpus.py`
  - validates generated files against deterministic source
  - validates exactly 24 pairs / 18 controls / six classes
  - validates pair JSON-pointer deltas
  - validates class/split balance
  - validates required adversarial attack set
  - validates coverage matrix and manifest digests
  - retains legacy security oracles
- `.github/workflows/ci.yml`
  - adds Python compile check
  - deterministic generation check
  - v3 corpus/coverage validation
  - drift scorer self-test
  - FPR/FNR quality-gate regression test
  - retains rustfmt/clippy/cargo test/reference benchmark
- `README.md`
  - documents benchmark v3, exact counts, canonical class mapping, metrics, public prediction protocol, quality gate, split limitations and reproducibility

## Tests added

1. Deterministic generated-suite integrity test
   - `python generate_science_suite.py --check`
2. Six-class corpus/coverage invariant validator
   - exact pair delta checking
   - 4 pair/class, 3 control/class
   - attack coverage and split coverage
   - digest validation
3. Scorer self-test
   - opaque/public stream anti-leak checks
   - TP/TN/FP/FN/FPR/FNR correctness
   - raw-score/AUC path
   - deliberate single FP/FN perturbation to prove error metrics move
4. FPR/FNR release-gate regression test
   - flips 3 safe pair baselines to FP
   - flips 2 risky mutated sides to FN
   - requires all five committed gate dimensions to report failure
5. Train/dev/test scorer paths
   - each split independently self-tested
6. Real predictions JSONL gate path
   - generated a temporary complete prediction file
   - ran the same public `verify_quality_gate.py predictions.jsonl` interface
   - temporary file deleted after validation

## Commands run + exact result

### Python syntax

```text
python -m py_compile generate_science_suite.py evaluate_quality.py verify_quality_gate.py verify_corpus.py run_benchmark.py
EXIT 0
```

### Deterministic generation

```text
python generate_science_suite.py --check
EXIT 0
generated benchmark files are deterministic and up to date
```

### Corpus verification

```text
python verify_corpus.py
EXIT 0
```

Observed:

- benchmark version: 3
- deterministic seed: 20260911
- legacy cases: 160
- legacy categories: 52
- adversarial/benign: 146 / 14
- drift pairs: 24
- hard controls: 18
- drift-science targets: 66
- positive/negative: 24 / 42
- pair counts per class: 4 for every one of 6 classes
- control counts per class: 3 for every one of 6 classes
- drift suite digest: `5d9546c8f74c9a7a72fde6da80b2ec1324d6a6022b9be0169f404666b1f6726b`
- all five retained security oracles: PASS

### Full drift scorer self-test

```text
python evaluate_quality.py self-test --focus drift
EXIT 0
```

Observed harness-oracle metrics:

- targets: 66
- TP: 24
- TN: 42
- FP: 0
- FN: 0
- FPR: 0.0
- FNR: 0.0
- pair count: 24
- pair accuracy: 1.0
- pair-baseline FPR: 0.0
- mutated-pair FNR: 0.0
- drift target-set digest: `f2bba246a24811e61549019d9daacfdad62180334b6ac4a3977c0fc0787c657f`

Important: đây là **scorer/harness oracle self-test**, không phải kết quả detector thật.

### Split self-tests

```text
python evaluate_quality.py self-test --focus drift --split train
EXIT 0 — 18 targets, 6 pairs, TP=6, TN=12, FP=0, FN=0

python evaluate_quality.py self-test --focus drift --split dev
EXIT 0 — 18 targets, 6 pairs, TP=6, TN=12, FP=0, FN=0

python evaluate_quality.py self-test --focus drift --split test
EXIT 0 — 30 targets, 12 pairs, TP=12, TN=18, FP=0, FN=0
```

### Quality-gate regression test

```text
python verify_quality_gate.py
EXIT 0
status: pass
```

Deliberate regression injected by the test produced:

- FPR = `0.071429` > `0.050000`
- FNR = `0.083333` > `0.050000`
- pair accuracy = `0.875000` < `0.900000`
- pair-baseline FPR = `0.125000` > `0.050000`
- pair FNR = `0.083333` > `0.050000`

All five expected regression failures were detected.

### Public predictions → real gate interface

A temporary full predictions JSONL was created using the harness oracle only to test the I/O contract, then:

```text
python verify_quality_gate.py .ai3-oracle-predictions.jsonl
EXIT 0
status: pass
failures: []
FPR: 0.0
FNR: 0.0
pair accuracy: 1.0
```

Temporary file was deleted immediately after the test.

### Rust formatting

```text
cargo fmt --all -- --check
EXIT 0
```

### Rust strict lint + tests

The first plain MCP shell attempt could not find MSVC `link.exe`. Investigation found Visual Studio 2022 Community at:

`C:\Program Files\Microsoft Visual Studio\2022\Community`

After loading its developer environment with `VsDevCmd.bat`:

```text
cargo clippy --locked --all-targets -- -D warnings
PASS

cargo test --locked
PASS
```

Exact Rust test summary:

```text
running 11 tests
11 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

Covered existing Rust tests include deny-before-dispatch, unknown backend, one-time approval, traversal rejection, secret redaction, canonical hash order invariance, digest mutation sensitivity, parent-prefix escape, corpus expectations and property tests.

### Legacy reference throughput harness

```text
python run_benchmark.py
EXIT 0
```

Observed local reference run:

- cases: 160
- iterations: 500
- operations: 80,000
- elapsed: 1272.3494 ms
- ops/sec: 62,875.8107
- last digest: `582de4780093741eb1286ba9580f3fb0db76c0d682676fa82e144c7336e1c31f`
- Python: 3.14.0
- Windows AMD64

This remains a canonical digest throughput harness, not production detector/runtime performance.

## Public API/schema changes

### `drift_pairs.json`

Breaking schema evolution from the previous experimental pair format to schema v2:

- adds benchmark version + deterministic seed + declared drift class list
- replaces ad-hoc category focus with canonical `drift_class`
- adds `attack_type`
- adds `split`
- adds `expected.ground_truth_reason`
- preserves minimal baseline/mutated form and exact `changed_paths`

### `evaluate_quality.py`

Scorer output moves to schema v3.

New output fields include:

- explicit `fnr`
- `fnr_95ci_wilson`
- `hard_controls`
- `per_drift_class_binary`
- `coverage_matrix`
- `raw_scores`
- pair `mutated_false_negative_rate`

Prediction input remains backward-compatible for required fields:

- required: `target_id`, `flagged`
- optional: `findings`, `decisions`, `evidence`
- new optional: `score` in `[0,1]`

Opaque target IDs are version-domain separated and therefore change under benchmark v3. Consumers must re-run `emit` rather than reuse v2 target IDs.

## Compatibility risks

1. Consumers that parse old `drift_pairs.json` schema v1 must update to v2.
2. Cached opaque target IDs from scorer v2 are invalid under v3 by design.
3. Benchmark result comparisons must only be made when `target_set_digest` is identical.
4. A detector integration that previously scored only the 160 legacy corpus should explicitly select `--focus corpus` if it wants old behavior; `--focus all` includes the v3 drift suite.
5. Public train/dev/test partitions are reproducible partitions, not a secret holdout.
6. Local Windows Rust commands require a VS Developer environment or equivalent MSVC PATH/LIB/INCLUDE setup. GitHub Actions runs on Ubuntu and does not have this Windows-specific requirement.

## Known remaining issues

1. No genuinely private/hidden test corpus is committed, because a public repository cannot provide a secret holdout. The protocol supports a hosted hidden set later.
2. `benchmark_baseline.json` is intentionally a harness/corpus-integrity oracle baseline, **not** measured performance from the production `proofdrift` detector.
3. A real detector quality result requires AI 1/AI 4/AI 5 cross-repo integration to feed actual `proofdrift` predictions into `verify_quality_gate.py`.
4. The sample size is deliberately reviewable rather than statistically huge. Wilson intervals are reported so zero observed FPR/FNR is not misread as zero population error.

## Merge notes

- Source branch: `ai3-bench-science`
- Scope is limited to `proofdrift-bench` benchmark corpus/harness/metrics/docs/CI.
- No `proofdrift` core engine or `proofdrift-spec` files were modified.
- Generated files must never be hand-edited independently of `generate_science_suite.py`; CI `--check` will reject stale artifacts.
- If another branch changes the legacy `corpus/*.json`, rerun `python generate_science_suite.py`, review the manifest digest change, and intentionally refresh any affected pinned baseline only after reviewing labels.
- AI 5 can wire production detector predictions into `python verify_quality_gate.py <predictions.jsonl>` as the cross-repo release gate.

## Score before/after out of 10 + evidence

### Before: 7.5/10

Evidence for the gap:

- strong 160-case adversarial corpus existed
- experimental 16 drift pairs existed
- scorer had useful metrics, but FNR was not surfaced as a first-class gate
- drift pairs were not balanced across the six canonical drift classes
- no explicit hard-negative matrix per class
- no deterministic versioned generator/manifest
- no train/dev/test partitioning
- no committed FPR/FNR regression threshold gate that proved it fails on injected regression

### After AI 3: 9.5/10 for benchmark engineering

Evidence:

- 24 balanced minimal pairs across all six canonical drift classes
- 18 extra hard-negative controls
- deterministic seed + generated artifacts + suite digest + target-set digest
- train/dev/test support and anti-label-leak emit protocol
- explicit TP/FP/TN/FN, FPR, FNR, Wilson intervals and optional ROC AUC
- pair-specific FPR/FNR and accuracy
- coverage matrix class × attack × split × decision
- committed 5% FPR/FNR gates + 90% pair gate
- regression injection proves all five gate dimensions trip correctly
- Python validation matrix PASS
- rustfmt PASS
- clippy PASS
- cargo test 11/11 PASS

The remaining 0.5 is not missing benchmark code in this branch. It is external validation: a genuinely hidden/private holdout and a measured production-detector run integrated from the other repos. Claiming 10/10 before those exist would overstate the evidence.
