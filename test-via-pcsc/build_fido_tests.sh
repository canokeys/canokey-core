#!/bin/bash
set -e

readonly FIDO2_TESTS_REF=dd55b6ba1ba2af4160af9aee3f0be8a1bc463e14

if [ ! -d u2f-ref-code ];then
git clone --depth 1 https://github.com/google/u2f-ref-code.git
pushd u2f-ref-code/u2f-tests/HID
git clone --depth 1 -b lollipop-release https://android.googlesource.com/platform/system/core
cd ../NFC; make
cd ../HID; make
popd
fi

git init fido2-tests
git -C fido2-tests remote add origin https://github.com/canokeys/fido2-tests.git
git -C fido2-tests fetch --depth 1 origin "$FIDO2_TESTS_REF"
git -C fido2-tests checkout --detach FETCH_HEAD
pushd fido2-tests
pip3 install --user -r requirements.txt
echo "Fixing a bug in python-fido2 0.9.3"
patch -p1 -u -d ~/.local/lib/python3.*/site-packages/fido2 <<EOF
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
patch -p1 -u -d ~/.local/lib/python3.*/site-packages/fido2 <../test-via-pcsc/fido2_SM2_COSE_key.patch
popd

if [ ! -d libfido2 ];then
git clone --depth 1 --branch 1.11.0 https://github.com/Yubico/libfido2.git
mkdir libfido2/build
pushd libfido2/build
cmake -DUSE_PCSC=ON ..
make -j2
else
pushd libfido2/build
fi
sudo make install
popd
