#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${ROOT_DIR}/.." && pwd)"
CONFIG_PATH="${ROOT_DIR}/benchmark_config.json"
PYTHON_BIN="${PYTHON_BIN:-${PROJECT_ROOT}/.venv/bin/python3}"
if [[ ! -x "${PYTHON_BIN}" ]]; then
  PYTHON_BIN="python3"
fi

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "raw_benchmark/run_projectx_benchmark.sh must run inside the Linux guest." >&2
  exit 1
fi

"${PYTHON_BIN}" - <<'PY'
import json
from pathlib import Path
cfg = json.loads(Path("raw_benchmark/benchmark_config.json").read_text())
workspace = Path(cfg["workspace_root"]).resolve()
blocked = [Path(item).resolve() for item in cfg["blocked_path_prefixes"]]
approved = [Path(item).resolve() for item in cfg["approved_guest_prefixes"]]
for required in ("malicious_dir", "clean_dir", "manifests_dir", "results_dir"):
    value = Path(cfg[required]).resolve()
    if any(value == item or item in value.parents for item in blocked):
        raise SystemExit(f"Blocked path for {required}: {value}")
    if not any(value == item or item in value.parents for item in approved):
        raise SystemExit(f"{required} is outside approved guest-only prefixes: {value}")
print("Guest-only path validation passed.")
PY

if [[ ! -x "$("${PYTHON_BIN}" - <<'PY'
import json
from pathlib import Path
cfg = json.loads(Path("raw_benchmark/benchmark_config.json").read_text())
print(cfg["projectx_binary"])
PY
)" ]]; then
  echo "ProjectX guest binary missing. Run raw_benchmark/setup_guest_env.sh first." >&2
  exit 1
fi

if [[ ! -f "$("${PYTHON_BIN}" - <<'PY'
import json
from pathlib import Path
cfg = json.loads(Path("raw_benchmark/benchmark_config.json").read_text())
print(Path(cfg["manifests_dir"]) / "malicious_manifest.json")
PY
)" ]]; then
  echo "Missing malicious manifest. Run raw_benchmark/download_malicious_corpus.py inside the guest first." >&2
  exit 1
fi

if [[ ! -f "$("${PYTHON_BIN}" - <<'PY'
import json
from pathlib import Path
cfg = json.loads(Path("raw_benchmark/benchmark_config.json").read_text())
print(Path(cfg["manifests_dir"]) / "clean_manifest.json")
PY
)" ]]; then
  echo "Missing clean manifest. Run raw_benchmark/build_clean_corpus.py inside the guest first." >&2
  exit 1
fi

"${PYTHON_BIN}" "${ROOT_DIR}/run_scans.py" --config "${CONFIG_PATH}"
"${PYTHON_BIN}" "${ROOT_DIR}/evaluate_results.py" --config "${CONFIG_PATH}"
"${PYTHON_BIN}" "${ROOT_DIR}/next_steps.py" --config "${CONFIG_PATH}"

RESULTS_DIR="$("${PYTHON_BIN}" - <<'PY'
import json
from pathlib import Path
cfg = json.loads(Path("raw_benchmark/benchmark_config.json").read_text())
print(Path(cfg["results_dir"]) / "latest")
PY
)"

PUBLISHED_DIR="$("${PYTHON_BIN}" - <<'PY'
from pathlib import Path
from raw_benchmark.common import LATEST_ARTIFACTS_DIR, load_config, publish_safe_artifacts
cfg = load_config(Path("raw_benchmark/benchmark_config.json"))
print(publish_safe_artifacts(Path(cfg["results_dir"]) / "latest", cfg))
PY
)"

echo "Raw ProjectX benchmark complete."
echo "Results: ${RESULTS_DIR}"
echo "Published safe artifacts: ${PUBLISHED_DIR}"
