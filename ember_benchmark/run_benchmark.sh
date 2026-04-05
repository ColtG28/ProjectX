#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATASET_DIR="${DATASET_DIR:-${ROOT_DIR}/data/raw/ember2018_v2/ember2018}"
PARITY_SAMPLE_SIZE="${PARITY_SAMPLE_SIZE:-1000}"
BENCHMARK_SAMPLE_SIZE="${BENCHMARK_SAMPLE_SIZE:-1000}"

source "${ROOT_DIR}/.venv/bin/activate"
export MPLCONFIGDIR="${ROOT_DIR}/cache/matplotlib"

python "${ROOT_DIR}/run_full_eval.py" \
  --dataset-dir "${DATASET_DIR}" \
  --parity-sample-size "${PARITY_SAMPLE_SIZE}" \
  --sample-size "${BENCHMARK_SAMPLE_SIZE}"
