pub mod compiler;
pub mod runner;

use self::runner::RuleConfidence;
use super::context::ScanContext;

pub fn run(ctx: &mut ScanContext) {
    let bundle = compiler::load_rule_bundle();
    ctx.rules_version = bundle.version.clone();
    ctx.push_view(super::types::View::new(
        "yara.rule_version",
        ctx.rules_version.clone(),
    ));
    ctx.log_event(
        "yara",
        format!(
            "Loaded {} YARA-style rules (version {})",
            bundle.rules.len(),
            ctx.rules_version
        ),
    );

    let matches = runner::run_on_views(&bundle.rules, &ctx.views);
    for m in matches {
        let weight = match m.confidence {
            RuleConfidence::High => 2.5,
            RuleConfidence::Medium => 2.0,
            RuleConfidence::Low => 1.4,
        };
        let confidence_label = match m.confidence {
            RuleConfidence::High => "high confidence",
            RuleConfidence::Medium => "medium confidence",
            RuleConfidence::Low => "low confidence",
        };
        let family = m
            .family
            .as_ref()
            .map(|family| format!(" family {family};"))
            .unwrap_or_default();
        ctx.push_finding(super::types::Finding::new(
            "YARA_MATCH",
            format!(
                "Local rule matched [{}]: {}{} literals {} in {}",
                confidence_label,
                m.name,
                family,
                m.matched_literals.join(", "),
                m.view_name
            ),
            weight,
        ));
    }
}

pub fn preload_keywords() -> usize {
    runner::preload_keywords()
}

pub fn refresh_rules() -> String {
    compiler::refresh_rule_bundle().version
}
