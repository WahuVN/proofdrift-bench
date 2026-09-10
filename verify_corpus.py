#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent
CORPUS = ROOT / "corpus"
SYNTHETIC_SECRET = "PROOFDRIFT_SYNTHETIC_SECRET_7F4B"


def canonical_digest(value):
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def normalize_relative(candidate):
    p = PurePosixPath(candidate.replace("\\", "/"))
    if p.is_absolute():
        return None
    parts = []
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


def redact(text, secrets):
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED]")
    return text


def deny_dispatch(decision, counter):
    if decision.upper() == "DENY":
        return False
    counter[0] += 1
    return True


def main():
    cases = []
    for path in sorted(CORPUS.glob("*.json")):
        obj = json.loads(path.read_text(encoding="utf-8"))
        required = {"schema_version", "id", "category", "benign", "input", "expected", "tags"}
        assert required <= set(obj), f"missing fields: {path.name}"
        assert obj["schema_version"] == "1"
        assert obj["expected"]["minimum_evidence"], path.name
        cases.append(obj)
    assert len(cases) >= 100, len(cases)
    assert any(c["benign"] for c in cases)
    assert any(not c["benign"] for c in cases)
    assert len({c["id"] for c in cases}) == len(cases)
    categories = sorted({c["category"] for c in cases})
    assert len(categories) >= 15

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

    a = {"b": 2, "a": {"y": 1, "x": 0}}
    b = {"a": {"x": 0, "y": 1}, "b": 2}
    assert canonical_digest(a) == canonical_digest(b)
    assert canonical_digest({"readOnly": True}) != canonical_digest({"readOnly": False})

    results = {
        "schema_version": "1",
        "suite": "proofdrift_security_corpus_verification",
        "cases": len(cases),
        "categories": len(categories),
        "benign_cases": sum(1 for c in cases if c["benign"]),
        "adversarial_cases": sum(1 for c in cases if not c["benign"]),
        "security_oracles": {
            "deny_before_dispatch": "pass",
            "synthetic_secret_redaction": "pass",
            "path_traversal_rejection": "pass",
            "canonical_digest_determinism": "pass",
            "digest_mutation_sensitivity": "pass",
        },
        "corpus_digest": canonical_digest(cases),
    }
    print(json.dumps(results, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
