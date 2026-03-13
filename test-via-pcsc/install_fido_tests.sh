#!/bin/bash
# Install FIDO tools + patch fido2 python lib (runs every time)
set -e

pushd fido2-tests
pip3 install --user -r requirements.txt
echo "Fixing a bug in python-fido2 0.9.3"
patch -p1 -u --forward -d ~/.local/lib/python3.*/site-packages/fido2 <<'EOF' || true
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
patch -p1 -u --forward -d ~/.local/lib/python3.*/site-packages/fido2 <../test-via-pcsc/fido2_SM2_COSE_key.patch || true
popd

pushd libfido2/build
sudo make install
popd
sudo ldconfig
