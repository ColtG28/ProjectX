#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${PROJECT_ROOT}/.venv"
PYTHON_BIN="${VENV_DIR}/bin/python3"

log() {
  printf '[bootstrap_vm] %s\n' "$1"
}

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "scripts/bootstrap_vm.sh must run inside the Ubuntu Linux VM." >&2
  exit 1
fi

if ! command -v sudo >/dev/null 2>&1; then
  echo "sudo is required for bootstrap_vm.sh" >&2
  exit 1
fi

log "Updating apt package lists."
sudo apt-get update

log "Installing Ubuntu dependencies."
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y \
  git \
  curl \
  build-essential \
  pkg-config \
  libssl-dev \
  ca-certificates \
  python3 \
  python3-pip \
  python3-venv

if [[ ! -x "${HOME}/.cargo/bin/rustup" ]]; then
  log "Installing Rust stable toolchain via rustup."
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain stable
fi

export PATH="${HOME}/.cargo/bin:${PATH}"
if ! command -v cargo >/dev/null 2>&1; then
  echo "cargo is still unavailable after rustup installation." >&2
  exit 1
fi

if [[ ! -d "${VENV_DIR}" ]]; then
  log "Creating Python virtual environment."
  python3 -m venv "${VENV_DIR}"
fi

log "Installing Python benchmark dependencies."
"${PYTHON_BIN}" -m pip install --upgrade pip
"${PYTHON_BIN}" -m pip install numpy scikit-learn

log "Building ProjectX CLI release binary."
cargo build --release --no-default-features

log "Preparing guest benchmark workspace."
PYTHON_BIN="${PYTHON_BIN}" bash "${PROJECT_ROOT}/raw_benchmark/setup_guest_env.sh"

log "Bootstrap complete."
log "Next: bash raw_benchmark/run_quick_test.sh"
