pub mod sections;
pub mod strings;
pub mod symbols;

use crate::r#static::types::Finding;

pub fn analyze(bytes: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(sections::check(bytes));
    findings.extend(symbols::check(bytes));
    findings.extend(strings::check(bytes));
    findings
}
