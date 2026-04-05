#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATASET_YEAR="${1:-2018}"
FEATURE_VERSION="${2:-2}"
DOWNLOAD_DIR="${ROOT_DIR}/data/downloads"
EXTRACT_DIR="${ROOT_DIR}/data/raw"

mkdir -p "${DOWNLOAD_DIR}" "${EXTRACT_DIR}"

case "${DATASET_YEAR}:${FEATURE_VERSION}" in
  "2017:1")
    FILE_NAME="ember_dataset.tar.bz2"
    URL="https://ember.elastic.co/ember_dataset.tar.bz2"
    SHA256="a5603de2f34f02ab6e21df7a0f97ec4ac84ddc65caee33fb610093dd6f9e1df9"
    TARGET_DIR="${EXTRACT_DIR}/ember2017_v1"
    ;;
  "2017:2")
    FILE_NAME="ember_dataset_2017_2.tar.bz2"
    URL="https://ember.elastic.co/ember_dataset_2017_2.tar.bz2"
    SHA256="60142493c44c11bc3fef292b216a293841283d86ff58384b5dc2d88194c87a6d"
    TARGET_DIR="${EXTRACT_DIR}/ember2017_v2"
    ;;
  "2018:2")
    FILE_NAME="ember_dataset_2018_2.tar.bz2"
    URL="https://ember.elastic.co/ember_dataset_2018_2.tar.bz2"
    SHA256="b6052eb8d350a49a8d5a5396fbe7d16cf42848b86ff969b77464434cf2997812"
    TARGET_DIR="${EXTRACT_DIR}/ember2018_v2"
    ;;
  *)
    echo "Unsupported EMBER dataset selection: year=${DATASET_YEAR} feature_version=${FEATURE_VERSION}" >&2
    exit 1
    ;;
esac

ARCHIVE_PATH="${DOWNLOAD_DIR}/${FILE_NAME}"

if [[ ! -f "${ARCHIVE_PATH}" ]]; then
  curl -L --fail --progress-bar "${URL}" -o "${ARCHIVE_PATH}"
fi

ACTUAL_SHA256="$(shasum -a 256 "${ARCHIVE_PATH}" | awk '{print $1}')"
if [[ "${ACTUAL_SHA256}" != "${SHA256}" ]]; then
  echo "Checksum mismatch for ${ARCHIVE_PATH}" >&2
  echo "Expected: ${SHA256}" >&2
  echo "Actual:   ${ACTUAL_SHA256}" >&2
  exit 1
fi

mkdir -p "${TARGET_DIR}"
tar -xjf "${ARCHIVE_PATH}" -C "${TARGET_DIR}"

cat <<EOF
EMBER dataset extracted.
Archive: ${ARCHIVE_PATH}
Target:  ${TARGET_DIR}
EOF
