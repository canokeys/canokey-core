#!/bin/bash
# Install FIDO tools + patch fido2 python lib (runs every time)
set -e

PYTHON_BIN="${PYTHON_BIN:-python3}"

pushd fido2-tests
patch -p1 -u --forward <../test-via-pcsc/fido2_retry_ctap2_init.patch || true
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
"${VENV_PYTHON}" - "${FIDO2_PACKAGE_DIR}" <<'PY'
from pathlib import Path
import sys

pkg = Path(sys.argv[1])

updates = [
    (
        pkg / "ctap2" / "blob.py",
        "                length=ln,\n",
        "                length=(size if offset == 0 else None),\n",
        "length=(size if offset == 0 else None),",
    ),
    (
        pkg / "pcsc.py",
        "            if (sw1, sw2) != SW_SUCCESS:\n"
        "                raise CtapError(CtapError.ERR.OTHER)  # TODO: Map from SW error\n",
        "            if (sw1, sw2) != SW_SUCCESS:\n"
        "                logger.error(\"NFC CTAP failure SW=%02X%02X resp=%s\", sw1, sw2, b2a_hex(resp))\n"
        "                raise CtapError(CtapError.ERR.OTHER)\n",
        "logger.error(\"NFC CTAP failure SW=%02X%02X resp=%s\", sw1, sw2, b2a_hex(resp))",
    ),
]

for path, old, new, marker in updates:
    text = path.read_text()
    if marker in text:
        continue
    if old not in text:
        raise SystemExit(f"failed to patch {path}")
    path.write_text(text.replace(old, new, 1))
PY
patch -p1 -u --forward -d "${FIDO2_PACKAGE_DIR}" <../test-via-pcsc/fido2_SM2_COSE_key.patch || true
popd

pushd libfido2/build
sudo make install
popd
sudo ldconfig
