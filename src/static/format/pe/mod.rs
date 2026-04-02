pub mod anomalies;
pub mod imports;
pub mod resources;
pub mod sections;
pub mod strings;

use crate::r#static::types::Finding;

pub fn analyze(bytes: &[u8]) -> Vec<Finding> {
    let mut findings = Vec::new();
    findings.extend(anomalies::check(bytes));
    findings.extend(imports::check(bytes));
    findings.extend(resources::check(bytes));
    findings.extend(sections::check(bytes));
    findings.extend(strings::check(bytes));
    findings
}
