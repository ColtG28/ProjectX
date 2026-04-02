pub mod sections;
pub mod strings;

use crate::r#static::types::Finding;

pub fn analyze(bytes: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(sections::check(bytes));
    findings.extend(strings::check(bytes));
    findings
}
