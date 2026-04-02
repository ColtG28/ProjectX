use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::snapshot::SnapshotStrategy;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxPlan {
    pub engine: String,
    pub image: String,
    pub sample_path: PathBuf,
    pub working_dir: PathBuf,
    pub read_only_root: bool,
    pub network_enabled: bool,
    pub cpu_limit: f32,
    pub memory_limit_mb: u64,
    pub snapshot_strategy: SnapshotStrategy,
    pub notes: Vec<String>,
}

impl SandboxPlan {
    pub fn for_sample(sample_path: &Path) -> Self {
        let engine =
            std::env::var("PROJECTX_SANDBOX_ENGINE").unwrap_or_else(|_| "docker".to_string());
        let network_enabled = std::env::var("PROJECTX_SANDBOX_NETWORK")
            .ok()
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let snapshot_strategy = match engine.as_str() {
            "virtualbox" | "qemu" => SnapshotStrategy::VmSnapshot,
            "overlay" => SnapshotStrategy::FilesystemOverlay,
            _ => SnapshotStrategy::ContainerLayerCommit,
        };
        Self {
            engine,
            image: "ubuntu:22.04".to_string(),
            sample_path: sample_path.to_path_buf(),
            working_dir: PathBuf::from("/analysis"),
            read_only_root: true,
            network_enabled,
            cpu_limit: 1.0,
            memory_limit_mb: 1024,
            snapshot_strategy,
            notes: vec![
                if network_enabled {
                    "Network enabled explicitly for detonation".to_string()
                } else {
                    "Network disabled by default".to_string()
                },
                "Sample should be mounted read-only unless detonation requires a writable copy".to_string(),
                "Promote to disposable VM when kernel drivers or persistence installers are suspected".to_string(),
            ],
        }
    }

    pub fn docker_args(&self) -> Vec<String> {
        let mut args = vec![
            "run".to_string(),
            "--rm".to_string(),
            "--cpus".to_string(),
            format!("{:.1}", self.cpu_limit),
            "--memory".to_string(),
            format!("{}m", self.memory_limit_mb),
            "-v".to_string(),
            format!(
                "{}:{}:ro",
                self.sample_path.display(),
                self.working_dir.join("sample.bin").display()
            ),
        ];

        if !self.network_enabled {
            args.push("--network".to_string());
            args.push("none".to_string());
        }
        if self.read_only_root {
            args.push("--read-only".to_string());
        }

        args.push(self.image.clone());
        args.push("/bin/sh".to_string());
        args.push("-lc".to_string());
        args.push("ls -l /analysis && sha256sum /analysis/sample.bin".to_string());
        args
    }

    pub fn docker_args_for_detonation(
        &self,
        timeout_ms: u64,
        output_dir: &Path,
        _trace_path: &Path,
        _stdout_path: &Path,
        _stderr_path: &Path,
    ) -> Vec<String> {
        let timeout_seconds = ((timeout_ms as f64) / 1000.0).ceil().max(1.0);
        let mut args = vec![
            "run".to_string(),
            "--rm".to_string(),
            "--cpus".to_string(),
            format!("{:.1}", self.cpu_limit),
            "--memory".to_string(),
            format!("{}m", self.memory_limit_mb),
            "--workdir".to_string(),
            self.working_dir.display().to_string(),
            "-v".to_string(),
            format!(
                "{}:{}:ro",
                self.sample_path.display(),
                self.working_dir.join("sample.bin").display()
            ),
            "-v".to_string(),
            format!("{}:/output", output_dir.display()),
            "--tmpfs".to_string(),
            "/tmp".to_string(),
        ];

        if !self.network_enabled {
            args.push("--network".to_string());
            args.push("none".to_string());
        }
        if self.read_only_root {
            args.push("--read-only".to_string());
        }

        args.push(self.image.clone());
        args.push("/bin/sh".to_string());
        args.push("-lc".to_string());
        args.push(format!(
            "cp {sample} /tmp/sample.bin && chmod +x /tmp/sample.bin && \
trace_cmd='timeout {timeout:.0}s /tmp/sample.bin'; \
if [ -f /tmp/sample.bin ] && [ \"$(head -c 2 /tmp/sample.bin)\" = '#!' ]; then trace_cmd='timeout {timeout:.0}s sh /tmp/sample.bin'; fi; \
if command -v strace >/dev/null 2>&1; then \
  strace -ff -s 256 -o /output/trace.raw sh -lc \"$trace_cmd\" >/output/stdout.log 2>/output/stderr.log; \
  cat /output/trace.raw* 2>/dev/null > /output/trace.log || true; \
else \
  echo 'strace unavailable' >/output/trace.log; \
  sh -lc \"$trace_cmd\" >/output/stdout.log 2>/output/stderr.log; \
fi",
            sample = self.working_dir.join("sample.bin").display(),
            timeout = timeout_seconds,
        ));
        args
    }
}

#[cfg(test)]
mod tests {
    use super::SandboxPlan;

    #[test]
    fn produces_read_only_docker_plan() {
        let plan = SandboxPlan::for_sample(std::path::Path::new("/tmp/sample.exe"));
        let args = plan.docker_args();
        assert!(args.contains(&"--read-only".to_string()));
        assert!(args.contains(&"none".to_string()));
    }
}
