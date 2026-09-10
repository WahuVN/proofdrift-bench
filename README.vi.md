# ProofDrift Bench

[English](README.md) | **Tiếng Việt**

[![Benchmark CI](https://github.com/WahuVN/proofdrift-bench/actions/workflows/ci.yml/badge.svg)](https://github.com/WahuVN/proofdrift-bench/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`proofdrift-bench` là **corpus adversarial và benchmark implementation-neutral** cho bài toán change control của coding agent. Repo được tách khỏi production engine để benchmark có thể đóng vai trò “trọng tài” thay vì tự chấm chính implementation của ProofDrift.

Mục tiêu chính là kiểm tra một detector có phân biệt đúng **security-relevant drift** với các input gần như giống hệt nhưng an toàn hay không, đồng thời đo cả false positive lẫn false negative.

## Benchmark v3

Repo giữ nguyên **160 legacy security cases**:

- 146 adversarial;
- 14 benign;
- 52 category.

Bên cạnh đó là drift-science suite deterministic với **66 target**:

- 24 minimal safe → risky drift pair, tương đương 48 pair target;
- 18 hard-negative control;
- tổng cộng 24 positive và 42 negative target;
- deterministic seed: `20260911`.

## Sáu nhóm drift chuẩn

| Nhóm chuẩn | Tên machine-readable |
| --- | --- |
| provenance drift | `provenance_drift` |
| capability drift | `capability_drift` |
| policy drift | `policy_drift` |
| runtime drift | `runtime_drift` |
| patch-impact drift | `patch_impact_drift` |
| test-proof drift | `test_proof_drift` |

Mỗi nhóm có đúng 4 positive minimal pair và 3 hard-negative control bổ sung. Mỗi nhóm có coverage ở `train`, `dev`, `test`; coverage matrix chứa các outcome `pass`, `warn`, `block`.

Các chiều adversarial gồm reordered fields, irrelevant noise, stale evidence, forged provenance, missing references, conflicting policy, capability escalation, replay và partial test proof. Suite còn có scope escalation, policy downgrade, request binding, TOCTOU command swap, patch-scope escape, dependency-policy change, stale test proof và missing execution receipt.

## Các file chính của v3

- `generate_science_suite.py` — source of truth deterministic cho generated suite.
- `drift_pairs.json` — 24 minimal pair, exact JSON-pointer `changed_paths` và ground-truth rationale.
- `hard_controls.json` — 18 hard negative.
- `coverage_matrix.json` — class × attack type × split × expected decision.
- `benchmark_manifest.json` — version, seed, count, distribution và digest.
- `evaluate_quality.py` — phát target không lộ label và chấm prediction.
- `benchmark_thresholds.json` — FPR/FNR và pair-quality gates đã commit.
- `benchmark_baseline.json` — pin target-set digest và harness baseline.
- `verify_quality_gate.py` — kiểm gate và chủ động bơm regression để chứng minh gate thực sự fail khi FPR/FNR xấu đi.
- `security_release_gate.py` — kiểm security/release invariant của benchmark.
- `BENCHMARK_METHODOLOGY.md` — protocol và cách diễn giải kết quả.

## Validate benchmark

```sh
python -m py_compile generate_science_suite.py evaluate_quality.py verify_quality_gate.py verify_corpus.py security_release_gate.py run_benchmark.py
python generate_science_suite.py --check
python verify_corpus.py
python evaluate_quality.py self-test --focus drift
python verify_quality_gate.py
python security_release_gate.py
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

`generate_science_suite.py --check` fail nếu generated artifact không còn khớp source deterministic. `verify_corpus.py` kiểm pair delta, class/split balance, attack coverage, hard negatives, coverage matrix, manifest digests và các legacy security invariant.

## Chạy detector bên ngoài

Xuất input mà detector được phép nhìn thấy:

```sh
python evaluate_quality.py emit --focus drift > targets.jsonl
```

Mỗi dòng chỉ có dạng:

```json
{"target_id":"target-...","input":{}}
```

Output cố tình không chứa label, drift class, attack type, split, pair membership, pair side hoặc ground-truth rationale để tránh rò đáp án.

Detector tạo một prediction cho từng target:

```json
{"target_id":"target-...","flagged":true,"score":0.93,"findings":[],"decisions":[],"evidence":[]}
```

Chỉ `target_id` và `flagged` là bắt buộc. `score` là tùy chọn trong `[0,1]`; nếu tất cả target có score thì scorer có thể báo ROC AUC. `findings`, `decisions` và `evidence` dùng cho semantic-quality metrics.

Chấm kết quả:

```sh
python evaluate_quality.py score predictions.jsonl --focus drift
```

Áp release gate:

```sh
python verify_quality_gate.py predictions.jsonl
```

## Threshold đã commit

Benchmark v3 yêu cầu:

- overall FPR ≤ 5%;
- overall FNR ≤ 5%;
- minimal-pair accuracy ≥ 90%;
- pair-baseline FPR ≤ 5%;
- mutated-pair FNR ≤ 5%.

Nếu một threshold bị vi phạm, gate thoát với status `2`, phù hợp để dùng trực tiếp trong CI.

## Metrics

Scorer báo:

- TP, FP, TN, FN;
- precision;
- recall/TPR;
- specificity;
- F1;
- balanced accuracy;
- FPR;
- FNR;
- Wilson 95% confidence interval cho FPR/FNR;
- minimal-pair accuracy;
- pair-baseline FPR;
- mutated-side TPR/FNR;
- prediction-changed rate;
- correct-direction-given-change;
- finding/decision/evidence quality;
- semantic-complete rate;
- optional raw-score coverage và ROC AUC;
- per-drift-class metrics và coverage summary.

Một detector flag tất cả có thể có FNR thấp nhưng FPR thảm họa. Detector flag không gì có thể có FPR thấp nhưng FNR thảm họa. Vì vậy benchmark bắt buộc đo cả hai phía và dùng minimal pairs để kiểm cùng một thay đổi gần-identical.

## Split và chống label leakage

Suite dùng assignment deterministic `train`, `dev`, `test`. Metadata split không có trong stream `emit`.

```sh
python evaluate_quality.py emit --focus drift --split test > test-targets.jsonl
python evaluate_quality.py score test-predictions.jsonl --focus drift --split test
```

Vì repo này công khai, các split chỉ là **reproducible evaluation partitions**, không phải secret holdout. Một hosted/private evaluator có thể dùng cùng format với case chưa công bố để tạo hidden test thật.

## Ground truth và tính tái lập

Mỗi positive pair chỉ thay đổi các JSON-pointer path đã khai báo. Baseline an toàn là negative, mutated side là positive, và mỗi pair chứa rationale cùng minimum evidence. Hard-negative control được gắn nhãn an toàn dù có reordering/noise/strengthening vô hại.

`benchmark_manifest.json` pin seed và suite digest. `benchmark_baseline.json` pin thêm opaque target-set digest. Vì vậy thay fixture hoặc label phải là thay đổi có chủ ý và có diff rõ ràng.

`evaluate_quality.py self-test` dùng ground truth để kiểm **scorer/harness**, không phải để tuyên bố production detector hoàn hảo. Điểm 100% của self-test không đồng nghĩa FPR/FNR ngoài thực tế bằng 0%.

## Legacy reference benchmark

```sh
python run_benchmark.py
```

Đây chỉ đo throughput của canonical digest trên legacy corpus; không phải benchmark end-to-end cho policy, broker, scanner, detector hoặc runtime.

## Fuzz seeds

`seeds/` chứa input synthetic deterministic cho parser, path, secret, approval, MCP, archive và evidence fuzzing. Không chứa credential thật.

## Repo liên quan

- `WahuVN/proofdrift` — production engine/CLI/runtime.
- `WahuVN/proofdrift-spec` — public wire contract và normative specification.

## Giấy phép

Apache License 2.0. Xem [LICENSE](LICENSE).
