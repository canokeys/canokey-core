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
FIDO2_SITE_PACKAGES_DIR="$(dirname "${FIDO2_PACKAGE_DIR}")"
echo "Fixing a bug in python-fido2 0.9.3"
if ! grep -q 'length=(size if offset == 0 else None)' "${FIDO2_PACKAGE_DIR}/ctap2/blob.py"; then
  blob_patch="$(mktemp)"
  cat >"${blob_patch}" <<'EOF'
--- fido2/ctap2/blob.py
+++ fido2/ctap2/blob.py
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
  patch -p0 -u --forward -d "${FIDO2_SITE_PACKAGES_DIR}" -i "${blob_patch}"
  rm -f "${blob_patch}"
fi
if ! grep -q 'NFC CTAP failure SW=%02X%02X resp=%s' "${FIDO2_PACKAGE_DIR}/pcsc.py"; then
  pcsc_patch="$(mktemp)"
  cat >"${pcsc_patch}" <<'EOF'
--- fido2/pcsc.py
+++ fido2/pcsc.py
@@ -200,9 +200,10 @@
                 # NFCCTAP_GETRESPONSE
                 resp, sw1, sw2 = self._chain_apdus(0x80, 0x11, 0x00, 0x00)
 
             if (sw1, sw2) != SW_SUCCESS:
-                raise CtapError(CtapError.ERR.OTHER)  # TODO: Map from SW error
+                logger.error("NFC CTAP failure SW=%02X%02X resp=%s", sw1, sw2, b2a_hex(resp))
+                raise CtapError(CtapError.ERR.OTHER)
 
             return resp
 
         raise CtapError(CtapError.ERR.KEEPALIVE_CANCEL)
EOF
  patch -p0 -u --forward -d "${FIDO2_SITE_PACKAGES_DIR}" -i "${pcsc_patch}"
  rm -f "${pcsc_patch}"
fi
patch -p1 -u --forward -d "${FIDO2_PACKAGE_DIR}" <../test-via-pcsc/fido2_SM2_COSE_key.patch || true
popd

pushd libfido2/build
if command -v sudo >/dev/null 2>&1; then
  sudo make install
else
  make install
fi
popd
if command -v sudo >/dev/null 2>&1; then
  sudo ldconfig
else
  ldconfig
fi
