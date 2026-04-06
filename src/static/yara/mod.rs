pub mod compiler;
pub mod runner;

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
        ctx.push_finding(super::types::Finding::new(
            "YARA_MATCH",
            format!("Local rule matched: {m}"),
            2.0,
        ));
    }
}

pub fn preload_keywords() -> usize {
    runner::preload_keywords()
}

pub fn refresh_rules() -> String {
    compiler::refresh_rule_bundle().version
}
