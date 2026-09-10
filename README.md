# ProofDrift Bench

[![Benchmark CI](https://github.com/WahuVN/proofdrift-bench/actions/workflows/ci.yml/badge.svg)](https://github.com/WahuVN/proofdrift-bench/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Adversarial regression corpus and benchmark harness for ProofDrift-style coding-agent change control.

The repository intentionally separates **security invariants** from production implementation. It contains deterministic synthetic cases, property tests and reference benchmark tooling that can be used by ProofDrift or other compatible implementations.

## Corpus

The current corpus contains **160 deterministic cases across 52 categories**: 146 adversarial and 14 benign controls. Covered themes include agent configuration poisoning, unpinned MCP dependencies, broad shell grants, schema rug pulls, approval replay/scope mismatch, destructive Git actions, nested shells, secret egress encodings, path/symlink/junction escape, archive limits, evidence tampering and patch/test-evidence gaps.

All secrets and attack payloads are synthetic and non-production.

## Validate

```sh
python verify_corpus.py
cargo test --locked
```

## Reference benchmark

```sh
python run_benchmark.py
```

The Python benchmark measures canonical corpus-digest throughput only. It is **not** a claim about end-to-end ProofDrift policy, broker, scanner or runtime performance. The committed reference result records the environment that produced it.

## Fuzz seeds

`seeds/` contains small deterministic inputs for parser, path, secret and evidence fuzzing. They contain no real credentials.

The implementation lives in [WahuVN/proofdrift](https://github.com/WahuVN/proofdrift). Public wire contracts live in [WahuVN/proofdrift-spec](https://github.com/WahuVN/proofdrift-spec).

## License

Apache License 2.0. See [LICENSE](LICENSE).
