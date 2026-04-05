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
  echo "raw_benchmark/setup_guest_env.sh must run inside the Linux guest." >&2
  exit 1
fi

"${PYTHON_BIN}" - <<'PY'
import json
from pathlib import Path
cfg = json.loads(Path("raw_benchmark/benchmark_config.json").read_text())
blocked = [Path(item).resolve() for item in cfg["blocked_path_prefixes"]]
approved = [Path(item).resolve() for item in cfg["approved_guest_prefixes"]]
for required in ("workspace_root", "malicious_dir", "clean_dir", "manifests_dir", "results_dir", "projectx_binary"):
    value = Path(cfg[required]).resolve()
    if any(value == item or item in value.parents for item in blocked):
        raise SystemExit(f"Blocked path for {required}: {value}")
    if required != "projectx_binary" and not any(value == item or item in value.parents for item in approved):
        raise SystemExit(f"{required} is outside approved guest-only prefixes: {value}")
    print(value)
for source in cfg.get("malicious_sources", []):
    if source.get("type") == "guest_local":
        print(Path(source["path"]).resolve())
PY

mapfile -t PATHS < <("${PYTHON_BIN}" - <<'PY'
import json
from pathlib import Path
cfg = json.loads(Path("raw_benchmark/benchmark_config.json").read_text())
for key in ("workspace_root", "malicious_dir", "clean_dir", "manifests_dir", "results_dir"):
    print(cfg[key])
print(Path(cfg["projectx_binary"]).parent)
for source in cfg.get("malicious_sources", []):
    if source.get("type") == "guest_local":
        print(source["path"])
PY
)

for path in "${PATHS[@]}"; do
  mkdir -p "${path}"
done

cargo build --release --no-default-features
PROJECTX_BIN_SRC="${PROJECT_ROOT}/target/release/ProjectX"
PROJECTX_BIN_DST="$("${PYTHON_BIN}" - <<'PY'
import json
from pathlib import Path
cfg = json.loads(Path("raw_benchmark/benchmark_config.json").read_text())
print(cfg["projectx_binary"])
PY
)"
install -m 0755 "${PROJECTX_BIN_SRC}" "${PROJECTX_BIN_DST}"

cat <<EOF
Guest benchmark environment prepared.

ProjectX binary: ${PROJECTX_BIN_DST}
Config: ${CONFIG_PATH}

Safety reminders:
- Keep malware only under approved guest paths from the config.
- Do not mount host folders read-write for malicious samples.
- Export only reports/logs with raw_benchmark/export_reports.py.
- Snapshot the guest before importing malware, then revert after the run.
EOF
