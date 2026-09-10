use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Expected {
    pub findings: Vec<String>,
    pub decisions: Vec<String>,
    pub minimum_evidence: Vec<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Case {
    pub schema_version: String,
    pub id: String,
    pub category: String,
    pub benign: bool,
    pub input: serde_json::Value,
    pub expected: Expected,
    pub tags: Vec<String>,
}

pub fn canonical_digest(value: &serde_json::Value) -> String {
    fn norm(v: &serde_json::Value) -> serde_json::Value {
        match v {
            serde_json::Value::Object(m) => {
                let mut b = BTreeMap::new();
                for (k, v) in m {
                    b.insert(k.clone(), norm(v));
                }
                serde_json::Value::Object(b.into_iter().collect())
            }
            serde_json::Value::Array(a) => serde_json::Value::Array(a.iter().map(norm).collect()),
            _ => v.clone(),
        }
    }
    let bytes = serde_json::to_vec(&norm(value)).expect("canonical json");
    format!("{:x}", Sha256::digest(bytes))
}

pub fn normalize_relative(root: &Path, candidate: &Path) -> Option<PathBuf> {
    if candidate.is_absolute() {
        return None;
    }
    let mut out = PathBuf::from(root);
    for c in candidate.components() {
        match c {
            Component::Normal(x) => out.push(x),
            Component::CurDir => {}
            Component::ParentDir => {
                if out == root || !out.pop() {
                    return None;
                }
            }
            _ => return None,
        }
    }
    if out.starts_with(root) {
        Some(out)
    } else {
        None
    }
}

pub fn redact(input: &str, secrets: &[&str]) -> String {
    let mut s = input.to_string();
    for secret in secrets {
        if !secret.is_empty() {
            s = s.replace(secret, "[REDACTED]");
        }
    }
    s
}

#[derive(Default)]
pub struct FakeDownstream {
    pub dispatch_count: usize,
}
pub fn broker_call(decision: &str, downstream: &mut FakeDownstream) -> bool {
    if decision.eq_ignore_ascii_case("DENY") {
        return false;
    }
    downstream.dispatch_count += 1;
    true
}

#[derive(Default)]
pub struct ApprovalStore {
    used: BTreeSet<String>,
}
impl ApprovalStore {
    pub fn consume(&mut self, token: &str) -> bool {
        if token.is_empty() {
            return false;
        }
        self.used.insert(token.to_string())
    }
}

pub fn enforcement_level(backend_known: bool, isolated_tested: bool) -> u8 {
    if backend_known && isolated_tested {
        2
    } else {
        1
    }
}

pub fn load_cases(dir: &Path) -> Result<Vec<Case>, Box<dyn std::error::Error>> {
    let mut out: Vec<Case> = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let p = e?.path();
        if p.extension().and_then(|x| x.to_str()) == Some("json") {
            out.push(serde_json::from_slice(&std::fs::read(&p)?)?);
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(out)
}
