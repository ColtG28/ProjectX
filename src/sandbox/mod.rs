pub mod container;
pub mod monitor;
pub mod runner;
pub mod snapshot;

use std::path::Path;

use crate::r#static::context::ScanContext;
use crate::r#static::types::SandboxPlanSummary;

pub fn plan_for_context(ctx: &mut ScanContext) {
    let plan = container::SandboxPlan::for_sample(&ctx.input_path);
    ctx.sandbox_plan = Some(SandboxPlanSummary {
        engine: plan.engine.clone(),
        network_enabled: plan.network_enabled,
        read_only_root: plan.read_only_root,
        snapshot_strategy: plan.snapshot_strategy.label().to_string(),
        notes: plan.notes.clone(),
    });
    ctx.push_view(crate::r#static::types::View::new(
        "sandbox.plan",
        serde_json::to_string(&ctx.sandbox_plan).unwrap_or_else(|_| "{}".to_string()),
    ));
    ctx.log_event(
        "sandbox",
        format!(
            "Prepared sandbox plan using {} with snapshot strategy {}",
            plan.engine,
            plan.snapshot_strategy.label()
        ),
    );
}

pub fn plan_for_path(path: &Path) -> container::SandboxPlan {
    container::SandboxPlan::for_sample(path)
}

pub fn execute_for_context(ctx: &mut ScanContext) {
    let plan = container::SandboxPlan::for_sample(&ctx.input_path);
    let result = runner::execute_plan(
        &plan,
        ctx.config.limits.sandbox_timeout_ms,
        ctx.config.limits.sandbox_output_bytes,
        ctx.config.limits.sandbox_event_limit,
        ctx.config.features.enable_runtime_yara,
    );

    if let Some(summary) = result.summary.clone() {
        if !summary.runtime_yara_hits.is_empty() {
            ctx.push_finding(crate::r#static::types::Finding::new(
                "SANDBOX_RUNTIME_YARA",
                format!(
                    "Dynamic sandbox output matched {} runtime signature(s)",
                    summary.runtime_yara_hits.len()
                ),
                1.5,
            ));
        }
        if summary.behavior.network_events > 0 {
            ctx.push_finding(crate::r#static::types::Finding::new(
                "SANDBOX_NETWORK_ACTIVITY",
                "Dynamic sandbox observed network activity attempts",
                2.0,
            ));
        }
        if summary.behavior.process_events > 0 {
            ctx.push_finding(crate::r#static::types::Finding::new(
                "SANDBOX_PROCESS_SPAWN",
                "Dynamic sandbox observed process creation activity",
                1.5,
            ));
        }
        if summary.behavior.file_events > 0 {
            ctx.push_finding(crate::r#static::types::Finding::new(
                "SANDBOX_FILE_ACTIVITY",
                "Dynamic sandbox observed filesystem modification activity",
                1.0,
            ));
        }

        ctx.dynamic_analysis = Some(summary.clone());
        ctx.push_view(crate::r#static::types::View::new(
            "sandbox.dynamic",
            serde_json::to_string(&summary).unwrap_or_else(|_| "{}".to_string()),
        ));
        ctx.log_event(
            "sandbox",
            format!(
                "Dynamic sandbox attempted={} executed={} events={} runtime_yara_hits={}",
                summary.attempted,
                summary.executed,
                summary.events.len(),
                summary.runtime_yara_hits.len()
            ),
        );
    }
}
