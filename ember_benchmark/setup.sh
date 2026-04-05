#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${ROOT_DIR}/.venv"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if [[ ! -d "${VENV_DIR}" ]]; then
  "${PYTHON_BIN}" -m venv --system-site-packages "${VENV_DIR}"
fi

source "${VENV_DIR}/bin/activate"
export PIP_DISABLE_PIP_VERSION_CHECK=1
mkdir -p "${ROOT_DIR}/cache/matplotlib"
export MPLCONFIGDIR="${ROOT_DIR}/cache/matplotlib"

if python - <<'PY'
import importlib
import sys

missing = []
for module_name in ("numpy", "pandas", "sklearn", "lightgbm"):
    try:
        importlib.import_module(module_name)
    except Exception:
        missing.append(module_name)

if missing:
    print("MISSING:" + ",".join(missing))
    sys.exit(3)
print("OK")
PY
then
  status=0
else
  status=$?
fi

if [[ ${status} -eq 3 ]]; then
  python -m pip install -r "${ROOT_DIR}/requirements-projectx.txt"
fi

python -m pip install --no-deps -e "${ROOT_DIR}/ember_repo"

cat <<EOF
EMBER benchmark environment ready.
Activate with:
  source "${VENV_DIR}/bin/activate"
EOF
