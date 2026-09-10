# Security Release Gate

A releasable ProofDrift Bench v3 must pass deterministic generation, corpus verification, scorer self-tests, FPR/FNR threshold sensitivity tests, and `security_release_gate.py`.

The release gate preserves the 160-case legacy security surface while independently verifying the v3 drift-science suite: all six drift classes, train/dev/test splits, safe-to-risky pair direction, hard-negative controls, semantic findings/decisions/evidence, ground-truth rationale, coverage-matrix consistency, and manifest counts.

CI stores the release-gate evidence beside the reference benchmark artifact for 30 days. Oracle/self-test scores remain harness evidence only and must never be presented as measured ProofDrift detector performance; real detector predictions must be scored separately through `verify_quality_gate.py <predictions.jsonl>`.
