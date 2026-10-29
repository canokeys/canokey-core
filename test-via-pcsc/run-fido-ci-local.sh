#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKSPACE_ROOT="$(cd "${REPO_ROOT}/.." && pwd)"

IMAGE_TAG="${IMAGE_TAG:-canokey-fido-ci-local}"
DOCKER_PLATFORM="${DOCKER_PLATFORM:-linux/amd64}"
BUILD_DIR="${BUILD_DIR:-build-fido-local}"
DOCKERFILE="${DOCKERFILE:-${SCRIPT_DIR}/Dockerfile.fido-local}"
ARTIFACT_DIR="${ARTIFACT_DIR:-${REPO_ROOT}/test-via-pcsc/local-artifacts}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker is required" >&2
  exit 1
fi

if ! docker image inspect "${IMAGE_TAG}" >/dev/null 2>&1; then
  docker build --platform "${DOCKER_PLATFORM}" -t "${IMAGE_TAG}" -f "${DOCKERFILE}" "${REPO_ROOT}"
fi

DOCKER_RUN_FLAGS=(--rm -i)
if [ -t 0 ] && [ -t 1 ]; then
  DOCKER_RUN_FLAGS+=( -t )
fi

docker run "${DOCKER_RUN_FLAGS[@]}" \
  --platform "${DOCKER_PLATFORM}" \
  -v "${WORKSPACE_ROOT}:/workspace" \
  -v "${ARTIFACT_DIR}:/artifacts" \
  -w /workspace/canokey-core \
  "${IMAGE_TAG}" \
  bash -s -- "${BUILD_DIR}" "$@" <<'EOF'
set -euo pipefail

BUILD_DIR="$1"
shift || true
WORKDIR="/workspace/canokey-core"

if [ "$#" -eq 0 ]; then
  set -- tests/standard/ tests/vendor/canokeys/
fi

for tool_dir in u2f-ref-code libfido2 fido2-tests; do
  if [ ! -d "${WORKDIR}/${tool_dir}" ] && [ -d "/root/${tool_dir}" ]; then
    cp -a "/root/${tool_dir}" "${WORKDIR}/${tool_dir}"
  fi
done

./test-via-pcsc/install_fido_tests.sh
FIDO_PYTHON="${WORKDIR}/fido2-tests/.venv/bin/python"

cmake -S . -B "${BUILD_DIR}" -DENABLE_TESTS=ON -DENABLE_DEBUG_OUTPUT=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build "${BUILD_DIR}" -j2

echo 0 >/tmp/canokey-test-up
echo 0 >/tmp/canokey-test-nfc
killall -9 pcscd 2>/dev/null || true

cp "${BUILD_DIR}/libu2f-virt-card.so" /usr/local/lib/
mkdir -p /etc/reader.conf.d
cp test-via-pcsc/pcscd-reader.conf /etc/reader.conf.d/

LD_PRELOAD="$(gcc -print-file-name=libasan.so) $(gcc -print-file-name=libubsan.so)" \
  pcscd --disable-polkit -a -f >/tmp/pcscd.log &
PCSCD_PID="$!"
cleanup() {
  kill "${PCSCD_PID}" 2>/dev/null || true
}
trap cleanup EXIT

sleep 15
timeout 1s pcsc_scan || true
chmod 777 /tmp/canokey-* 2>/dev/null || true
chown root:root /tmp/canokey-* 2>/dev/null || true

"${FIDO_PYTHON}" - <<'PY'
import importlib.metadata
import pathlib
import sys
import fido2
print("python:", sys.executable)
print("fido2_version:", importlib.metadata.version("fido2"))
print("fido2_path:", pathlib.Path(fido2.__file__).resolve())
PY

echo 1 >/tmp/canokey-test-nfc
pushd fido2-tests >/dev/null
for target in "$@"; do
  target_name="$(printf '%s' "${target}" | tr '/:[]' '_____' | tr -cd '[:alnum:]_.-')"
  pytest_log="/artifacts/${target_name}.pytest.log"
  if ! "${FIDO_PYTHON}" -m pytest --color=yes --vendor canokeys --nfc "${target}" 2>&1 | tee "${pytest_log}"; then
    cp /tmp/pcscd.log "/artifacts/${target_name}.pcscd.log" 2>/dev/null || true
    echo "===== /tmp/pcscd.log ====="
    cat /tmp/pcscd.log || true
    exit 1
  fi
done
popd >/dev/null
EOF
