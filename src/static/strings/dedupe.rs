use std::collections::HashSet;

pub fn stable_dedupe(values: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();

    for value in values {
        if seen.insert(value.clone()) {
            out.push(value);
        }
    }

    out
}
