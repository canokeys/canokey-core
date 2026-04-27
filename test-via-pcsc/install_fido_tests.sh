#!/bin/bash
# Install FIDO tools + patch fido2 python lib (runs every time)
set -e

PYTHON_BIN="${PYTHON_BIN:-python3}"

pushd fido2-tests
VENV_DIR="${PWD}/.venv"
if [ ! -x "${VENV_DIR}/bin/python" ]; then
  "${PYTHON_BIN}" -m venv "${VENV_DIR}"
fi
VENV_PYTHON="${VENV_DIR}/bin/python"
"${VENV_PYTHON}" -m pip install --upgrade pip setuptools wheel
tmp_requirements="$(mktemp)"
grep -v '^pyscard\b' requirements.txt >"${tmp_requirements}"
"${VENV_PYTHON}" -m pip install -r "${tmp_requirements}"
rm -f "${tmp_requirements}"
# fido2==0.9.3 still imports smartcard.pcsc.PCSCContext, removed by newer pyscard.
"${VENV_PYTHON}" -m pip install "pyscard==2.0.7"
FIDO2_PACKAGE_DIR="$("${VENV_PYTHON}" - <<'PY'
from importlib.util import find_spec
from pathlib import Path

spec = find_spec("fido2")
if spec is None or spec.origin is None:
    raise SystemExit("python-fido2 is not installed")
print(Path(spec.origin).resolve().parent)
PY
)"
echo "Fixing a bug in python-fido2 0.9.3"
patch -p1 -u --forward -d "${FIDO2_PACKAGE_DIR}" <<'EOF' || true
--- fido2/ctap2/blob.py 2023-08-22 21:09:59.905129124 +0800
+++ fido2.fix/ctap2/blob.py  2023-08-22 21:14:07.014840263 +0800
@@ -150,7 +150,7 @@
             self.ctap.large_blobs(
                 offset,
                 set=_set,
-                length=ln,
+                length=(size if offset == 0 else None),
                 pin_uv_protocol=pin_uv_protocol,
                 pin_uv_param=pin_uv_param,
             )
EOF
patch -p1 -u --forward -d "${FIDO2_PACKAGE_DIR}" <../test-via-pcsc/fido2_SM2_COSE_key.patch || true
popd

pushd libfido2/build
make install
popd
ldconfig
