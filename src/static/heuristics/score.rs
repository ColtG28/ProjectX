use crate::r#static::types::Finding;

pub fn calculate(findings: &[Finding]) -> f64 {
    let total_weight: f64 = findings.iter().map(|f| f.weight).sum();
    total_weight.min(10.0)
}
