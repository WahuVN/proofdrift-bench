# Contributing

Add cases that isolate one security invariant whenever possible. Every corpus case must have a stable ID, category, benign/adversarial label, expected findings or decisions, and minimum evidence expectations.

Before opening a pull request:

```sh
python verify_corpus.py
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
```

Do not add real secrets, private repository content, destructive live endpoints or payloads that require external side effects. Keep exploit material synthetic and self-contained.
