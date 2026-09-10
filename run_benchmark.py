#!/usr/bin/env python3
import json, platform, sys, time
from pathlib import Path
from verify_corpus import canonical_digest

ROOT = Path(__file__).resolve().parent
CASES = [json.loads(p.read_text(encoding="utf-8")) for p in sorted((ROOT / "corpus").glob("*.json"))]
ITERATIONS = 500
start = time.perf_counter()
last = None
for _ in range(ITERATIONS):
    for case in CASES:
        last = canonical_digest(case)
elapsed = time.perf_counter() - start
ops = len(CASES) * ITERATIONS
result = {
    "schema_version": "1",
    "benchmark": "proofdrift_canonical_corpus_digest_python_reference",
    "note": "Reference harness only; not a production ProofDrift performance claim.",
    "cases": len(CASES),
    "iterations": ITERATIONS,
    "operations": ops,
    "elapsed_ms": elapsed * 1000.0,
    "ops_per_sec": ops / elapsed if elapsed else None,
    "environment": {
        "python": sys.version.split()[0],
        "os": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
    },
    "last_digest": last,
}
print(json.dumps(result, indent=2, sort_keys=True))
