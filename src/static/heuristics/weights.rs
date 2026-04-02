use std::collections::HashMap;

pub fn defaults() -> HashMap<String, f64> {
    HashMap::from([
        ("FILE_SMALL".to_string(), 1.0),
        ("MAGIC_MISMATCH".to_string(), 2.5),
        ("YARA_MATCH".to_string(), 2.0),
    ])
}
