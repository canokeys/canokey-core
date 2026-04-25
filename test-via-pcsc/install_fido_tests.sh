#!/bin/bash
# Install FIDO tools + patch fido2 python lib (runs every time)
set -e

PYTHON_BIN="${PYTHON_BIN:-python3}"

pushd fido2-tests
"${PYTHON_BIN}" -m pip install --user -r requirements.txt
FIDO2_PACKAGE_DIR="$("${PYTHON_BIN}" - <<'PY'
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
"${PYTHON_BIN}" - <<'PY'
from pathlib import Path

path = Path("tests/conftest.py")
text = path.read_text()

if "import traceback\n" not in text:
    text = text.replace("import os\n", "import os\nimport traceback\n")

old_import = "from fido2.ctap2 import AttestedCredentialData, PinProtocolV1\n"
new_import = (
    "from fido2.ctap2 import AttestedCredentialData, ClientPin, Ctap2, PinProtocolV1\n"
)
if old_import in text:
    text = text.replace(old_import, new_import)

needle = """    def find_device(self, nfcInterfaceOnly=False):\n"""
helper = """    def _init_client(self, dev):\n        try:\n            ctap2 = Ctap2(dev)\n            print(\"CTAP2 probe info:\", ctap2.info)\n        except Exception as e:\n            print(\"CTAP2 constructor failed: %r\" % (e,))\n            traceback.print_exc()\n            raise\n\n        try:\n            ClientPin(ctap2)\n            print(\"ClientPin probe: supported\")\n        except ValueError as e:\n            print(\"ClientPin probe: unavailable (%r)\" % (e,))\n        except Exception as e:\n            print(\"ClientPin probe failed: %r\" % (e,))\n            traceback.print_exc()\n            raise\n\n        client = Fido2Client(dev, self.origin)\n        if not hasattr(client, \"ctap2\"):\n            raise RuntimeError(\"Fido2Client unexpectedly fell back to CTAP1\")\n        return client, client.ctap2\n\n"""
if "def _init_client(self, dev):\n" not in text and needle in text:
    text = text.replace(needle, helper + needle)

old_init = """        self.client = Fido2Client(dev, self.origin)\n        self.ctap2 = self.client.ctap2\n"""
new_init = """        self.client, self.ctap2 = self._init_client(dev)\n"""
if old_init in text:
    text = text.replace(old_init, new_init)

path.write_text(text)
PY
popd

pushd libfido2/build
sudo make install
popd
sudo ldconfig
