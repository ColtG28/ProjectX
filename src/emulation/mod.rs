pub mod api_hash;
pub mod pe;
pub mod script;
pub mod strings;

use std::time::Instant;

use crate::r#static::context::ScanContext;
use crate::r#static::types::{EmulationSummary, ExtractedArtifact, Finding, View};
use crate::r#static::yara::{compiler, runner};

#[derive(Debug, Clone, Copy)]
pub struct EmulationConfig {
    pub instruction_budget: usize,
    pub timeout_ms: u64,
    pub runtime_yara: bool,
    pub collect_multiple_outputs: bool,
}

impl EmulationConfig {
    pub fn from_context(ctx: &ScanContext) -> Self {
        Self {
            instruction_budget: ctx.config.limits.max_emulation_steps,
            timeout_ms: ctx.config.limits.emulation_timeout_ms,
            runtime_yara: ctx.config.features.enable_runtime_yara,
            collect_multiple_outputs: true,
        }
    }
}

#[derive(Debug, Default)]
pub(crate) struct EmulationState {
    findings: Vec<Finding>,
    artifacts: Vec<ExtractedArtifact>,
    derived_outputs: Vec<String>,
    resolved_api_hashes: Vec<String>,
    runtime_yara_hits: Vec<String>,
    steps_used: usize,
    timed_out: bool,
}

pub fn run(ctx: &mut ScanContext) {
    let config = EmulationConfig::from_context(ctx);
    let started = Instant::now();
    let inputs = ctx
        .text_values()
        .into_iter()
        .take(ctx.config.limits.max_string_values)
        .map(str::to_string)
        .collect::<Vec<_>>();
    let mut state = EmulationState::default();

    script::emulate_powershell(&inputs, &mut state, config, started);
    script::emulate_javascript(&inputs, &mut state, config, started);
    script::emulate_vba(&inputs, &mut state, config, started);
    strings::detect_decryption_loops(&inputs, &mut state, config, started);
    pe::emulate_loader(&ctx.bytes, &inputs, &mut state, config, started);
    api_hash::resolve_in_inputs(&inputs, &mut state, config, started);

    if config.runtime_yara && !state.derived_outputs.is_empty() && !state.timed_out {
        let bundle = compiler::load_rule_bundle();
        let views = state
            .derived_outputs
            .iter()
            .enumerate()
            .map(|(index, content)| View::new(format!("emulation.output.{index}"), content))
            .collect::<Vec<_>>();
        state.runtime_yara_hits = runner::run_on_views(&bundle.rules, &views);
        for hit in &state.runtime_yara_hits {
            state.findings.push(Finding::new(
                "EMULATION_RUNTIME_YARA",
                format!("Runtime-emulated artifact matched signature: {hit}"),
                1.5,
            ));
        }
    }

    let finding_count = state.findings.len();
    for finding in std::mem::take(&mut state.findings) {
        ctx.push_finding(finding);
    }
    for artifact in state.artifacts.iter().cloned() {
        ctx.push_artifact(artifact);
    }

    if !state.derived_outputs.is_empty() {
        ctx.decoded_strings.extend(
            state
                .derived_outputs
                .iter()
                .take(ctx.config.limits.max_decoded_strings)
                .cloned(),
        );
    }

    let summary = EmulationSummary {
        executed: true,
        instruction_budget: config.instruction_budget,
        steps_used: state.steps_used,
        timed_out: state.timed_out,
        runtime_yara_hits: std::mem::take(&mut state.runtime_yara_hits),
        resolved_api_hashes: std::mem::take(&mut state.resolved_api_hashes),
        derived_artifacts: state.artifacts.clone(),
    };
    ctx.push_view(View::new(
        "emulation.summary",
        serde_json::to_string(&summary).unwrap_or_else(|_| "{}".to_string()),
    ));
    ctx.emulation = Some(summary);
    ctx.log_event(
        "emulation",
        format!(
            "Emulation completed with {} derived artifacts, {} findings, timed_out={}",
            state.artifacts.len(),
            finding_count,
            state.timed_out
        ),
    );
}

fn consume_budget(state: &mut EmulationState, config: EmulationConfig, started: Instant) -> bool {
    state.steps_used = state.steps_used.saturating_add(1);
    if state.steps_used > config.instruction_budget
        || started.elapsed().as_millis() as u64 >= config.timeout_ms
    {
        state.timed_out = true;
        return false;
    }
    true
}

fn push_output(
    state: &mut EmulationState,
    artifact_name: impl Into<String>,
    content: String,
    kind: &'static str,
) {
    if content.trim().is_empty() || state.derived_outputs.contains(&content) {
        return;
    }
    state.artifacts.push(ExtractedArtifact::new(
        artifact_name,
        kind,
        1,
        content.len(),
    ));
    state.derived_outputs.push(content);
}

pub(crate) fn maybe_push_multiple_outputs<I>(
    state: &mut EmulationState,
    prefix: &str,
    values: I,
    kind: &'static str,
    config: EmulationConfig,
) where
    I: IntoIterator<Item = String>,
{
    for (index, value) in values.into_iter().enumerate() {
        if !config.collect_multiple_outputs {
            push_output(state, prefix.to_string(), value, kind);
            break;
        }
        push_output(state, format!("{prefix}.{index}"), value, kind);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::{api_hash, consume_budget, script, EmulationConfig, EmulationState};

    #[test]
    fn budget_stops_execution() {
        let config = EmulationConfig {
            instruction_budget: 1,
            timeout_ms: 5_000,
            runtime_yara: false,
            collect_multiple_outputs: true,
        };
        let started = Instant::now();
        let mut state = EmulationState::default();
        assert!(consume_budget(&mut state, config, started));
        assert!(!consume_budget(&mut state, config, started));
        assert!(state.timed_out);
    }

    #[test]
    fn resolves_api_hash_candidates() {
        let config = EmulationConfig {
            instruction_budget: 128,
            timeout_ms: 5_000,
            runtime_yara: false,
            collect_multiple_outputs: true,
        };
        let started = Instant::now();
        let mut state = EmulationState::default();
        let hash = api_hash::hash_name_for_resolution("VirtualAlloc");
        api_hash::resolve_in_inputs(&[format!("0x{hash:08X}")], &mut state, config, started);
        assert!(state
            .resolved_api_hashes
            .iter()
            .any(|hit| hit.contains("VirtualAlloc")));
    }

    #[test]
    fn emulates_js_charcode_sequences() {
        let config = EmulationConfig {
            instruction_budget: 256,
            timeout_ms: 5_000,
            runtime_yara: false,
            collect_multiple_outputs: true,
        };
        let started = Instant::now();
        let mut state = EmulationState::default();
        script::emulate_javascript(
            &["eval(String.fromCharCode(97,108,101,114,116,40,49,41))".to_string()],
            &mut state,
            config,
            started,
        );
        assert!(state
            .derived_outputs
            .iter()
            .any(|output| output.contains("alert(1)")));
    }
}
