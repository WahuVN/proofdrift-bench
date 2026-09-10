use proofdrift_security_bench::{canonical_digest, load_cases};
use serde_json::json;
use std::time::Instant;
fn main() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let cases = load_cases(&root.join("corpus")).expect("load corpus");
    let env = json!({"os":std::env::consts::OS,"arch":std::env::consts::ARCH,"rustc":option_env!("RUSTC_VERSION").unwrap_or("unknown")});
    let start = Instant::now();
    let mut acc = String::new();
    for _ in 0..200 {
        for c in &cases {
            acc = canonical_digest(&serde_json::to_value(c).unwrap());
        }
    }
    let elapsed = start.elapsed();
    let result = json!({"schema_version":"1","benchmark":"canonical_corpus_digest","cases":cases.len(),"iterations":200,"operations":cases.len()*200,"elapsed_ms":elapsed.as_secs_f64()*1000.0,"ops_per_sec":((cases.len()*200) as f64/elapsed.as_secs_f64()),"environment":env,"last_digest":acc});
    println!("{}", serde_json::to_string_pretty(&result).unwrap());
}
