#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${BUILD_DIR:-${SCRIPT_DIR}/build}"
CMAKE_GENERATOR="${CMAKE_GENERATOR:-Unix Makefiles}"
LIEF="${SENTINELX_USE_LIEF:-ON}"

echo "[+] Configuring CMake (LIEF=${LIEF})..."
cmake -S "${SCRIPT_DIR}" -B "${BUILD_DIR}" -G "${CMAKE_GENERATOR}" \
    -DSENTINELX_USE_LIEF="${LIEF}"

echo "[+] Building..."
cmake --build "${BUILD_DIR}" --config Release

BIN="${BUILD_DIR}/SentinelX"

UNAME_OUT="$(uname -s || echo "unknown")"
case "${UNAME_OUT}" in
    MINGW*|MSYS*)
        BIN="${BUILD_DIR}/Release/SentinelX.exe"
        ;;
esac

if [[ $# -gt 0 ]]; then
    echo "[+] Running SentinelX with args: $*"
    "${BIN}" "$@"
else
    echo "[+] Build finished. Binary at: ${BIN}"
    echo "    Example: ${BIN} --source ./test --binary ./your_binary"
fi
