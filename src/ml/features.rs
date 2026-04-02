use crate::r#static::context::ScanContext;

#[derive(Debug, Clone, Default)]
pub struct FeatureVector {
    pub finding_count: usize,
    pub suspicious_weight: f64,
    pub decoded_count: usize,
    pub artifact_count: usize,
    pub nested_depth: usize,
    pub yara_hits: usize,
    pub emulation_runtime_hits: usize,
    pub has_macro_indicator: bool,
    pub has_network_indicator: bool,
    pub dynamic_network_events: usize,
    pub dynamic_process_events: usize,
    pub dynamic_file_events: usize,
    pub dynamic_runtime_yara_hits: usize,
}

pub fn extract(ctx: &ScanContext) -> FeatureVector {
    let nested_depth = ctx
        .views
        .iter()
        .find(|view| view.name == "format.nested_depth")
        .and_then(|view| view.content.parse::<usize>().ok())
        .unwrap_or(0);
    let yara_hits = ctx
        .findings
        .iter()
        .filter(|finding| finding.code == "YARA_MATCH")
        .count();
    let emulation_runtime_hits = ctx
        .emulation
        .as_ref()
        .map(|summary| summary.runtime_yara_hits.len())
        .unwrap_or(0);

    FeatureVector {
        finding_count: ctx.findings.len(),
        suspicious_weight: ctx.findings.iter().map(|finding| finding.weight).sum(),
        decoded_count: ctx.decoded_strings.len(),
        artifact_count: ctx.artifacts.len(),
        nested_depth,
        yara_hits,
        emulation_runtime_hits,
        has_macro_indicator: ctx
            .findings
            .iter()
            .any(|finding| finding.code.contains("MACRO")),
        has_network_indicator: ctx
            .findings
            .iter()
            .any(|finding| finding.message.to_ascii_lowercase().contains("http")),
        dynamic_network_events: ctx
            .dynamic_analysis
            .as_ref()
            .map(|summary| summary.behavior.network_events)
            .unwrap_or(0),
        dynamic_process_events: ctx
            .dynamic_analysis
            .as_ref()
            .map(|summary| summary.behavior.process_events)
            .unwrap_or(0),
        dynamic_file_events: ctx
            .dynamic_analysis
            .as_ref()
            .map(|summary| summary.behavior.file_events)
            .unwrap_or(0),
        dynamic_runtime_yara_hits: ctx
            .dynamic_analysis
            .as_ref()
            .map(|summary| summary.runtime_yara_hits.len())
            .unwrap_or(0),
    }
}

#[cfg(test)]
mod tests {
    use crate::r#static::config::ScanConfig;
    use crate::r#static::context::ScanContext;
    use crate::r#static::types::{Finding, View};

    use super::extract;

    #[test]
    fn extracts_basic_features() {
        let path = std::env::temp_dir().join("projectx_ml_features.txt");
        std::fs::write(&path, "hello").unwrap();
        let mut ctx = ScanContext::from_path(&path, ScanConfig::default()).unwrap();
        ctx.findings.push(Finding::new("YARA_MATCH", "hit", 2.0));
        ctx.findings
            .push(Finding::new("OFFICE_MACRO", "macro", 2.0));
        ctx.decoded_strings.push("decoded".to_string());
        ctx.push_view(View::new("format.nested_depth", "2"));

        let vector = extract(&ctx);
        assert_eq!(vector.finding_count, 2);
        assert_eq!(vector.nested_depth, 2);
        assert!(vector.has_macro_indicator);

        let _ = std::fs::remove_file(path);
    }
}
