use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::r#static::types::DynamicAnalysisSummary;
use crate::r#static::yara::{compiler, runner};

use super::container::SandboxPlan;
use super::monitor;
use super::snapshot::{build_snapshot_state, SnapshotStrategy};

#[derive(Debug, Clone, Default)]
pub struct SandboxExecutionResult {
    pub summary: Option<DynamicAnalysisSummary>,
}

pub fn execute_plan(
    plan: &SandboxPlan,
    timeout_ms: u64,
    output_limit: usize,
    max_events: usize,
    runtime_yara: bool,
) -> SandboxExecutionResult {
    let snapshot_id = format!(
        "sandbox-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or(0)
    );
    let snapshot =
        build_snapshot_state(SnapshotStrategy::ContainerLayerCommit, snapshot_id.clone());

    if !docker_available() {
        return SandboxExecutionResult {
            summary: Some(DynamicAnalysisSummary {
                attempted: false,
                executed: false,
                timed_out: false,
                engine: plan.engine.clone(),
                snapshot_id: Some(snapshot.snapshot_id),
                revert_command: Some(snapshot.revert_command),
                error: Some(format!(
                    "{} is not available for dynamic detonation",
                    plan.engine
                )),
                ..DynamicAnalysisSummary::default()
            }),
        };
    }

    let workspace = temp_output_dir();
    let _ = fs::create_dir_all(&workspace);
    let trace_path = workspace.join("trace.log");
    let stdout_path = workspace.join("stdout.log");
    let stderr_path = workspace.join("stderr.log");

    let args = plan.docker_args_for_detonation(
        timeout_ms,
        &workspace,
        &trace_path,
        &stdout_path,
        &stderr_path,
    );
    let status = Command::new("docker").args(&args).status();

    let stdout_preview = read_limited(&stdout_path, output_limit);
    let stderr_preview = read_limited(&stderr_path, output_limit);
    let trace = fs::read_to_string(&trace_path).unwrap_or_default();
    let events = monitor::parse_trace_log(&trace, max_events);
    let behavior = monitor::into_dynamic_summary(&events);
    let dynamic_events = monitor::into_dynamic_events(&events);
    let runtime_yara_hits = if runtime_yara {
        let bundle = compiler::load_rule_bundle();
        let views = vec![
            crate::r#static::types::View::new("sandbox.stdout", &stdout_preview),
            crate::r#static::types::View::new("sandbox.stderr", &stderr_preview),
            crate::r#static::types::View::new("sandbox.trace", &trace),
        ];
        runner::run_on_views(&bundle.rules, &views)
    } else {
        Vec::new()
    };

    let summary = match status {
        Ok(status) => DynamicAnalysisSummary {
            attempted: true,
            executed: true,
            timed_out: !status.success()
                && stderr_preview.to_ascii_lowercase().contains("timed out"),
            engine: plan.engine.clone(),
            exit_code: status.code(),
            stdout_preview,
            stderr_preview,
            behavior,
            events: dynamic_events,
            runtime_yara_hits,
            snapshot_id: Some(snapshot.snapshot_id),
            revert_command: Some(snapshot.revert_command),
            error: None,
        },
        Err(error) => DynamicAnalysisSummary {
            attempted: true,
            executed: false,
            timed_out: false,
            engine: plan.engine.clone(),
            stdout_preview,
            stderr_preview,
            behavior,
            events: dynamic_events,
            runtime_yara_hits,
            snapshot_id: Some(snapshot.snapshot_id),
            revert_command: Some(snapshot.revert_command),
            error: Some(format!("Failed to execute docker sandbox: {}", error)),
            ..DynamicAnalysisSummary::default()
        },
    };

    SandboxExecutionResult {
        summary: Some(summary),
    }
}

fn docker_available() -> bool {
    if std::env::var("PROJECTX_SANDBOX_ENGINE")
        .map(|value| value != "docker")
        .unwrap_or(false)
    {
        return false;
    }
    Command::new("docker")
        .arg("info")
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn temp_output_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "projectx_sandbox_{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ))
}

fn read_limited(path: &PathBuf, output_limit: usize) -> String {
    let mut text = fs::read_to_string(path).unwrap_or_default();
    if text.len() > output_limit {
        text.truncate(output_limit);
    }
    text
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::execute_plan;
    use crate::sandbox::container::SandboxPlan;

    #[test]
    fn returns_graceful_summary_without_docker() {
        let plan = SandboxPlan::for_sample(Path::new("/tmp/sample.bin"));
        let result = execute_plan(&plan, 1000, 2048, 64, true);
        let summary = result.summary.expect("summary");
        assert_eq!(summary.engine, "docker");
    }
}
