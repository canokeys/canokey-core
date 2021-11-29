#!/bin/bash
set -e
git clone --depth 1 https://github.com/google/u2f-ref-code.git
pushd u2f-ref-code/u2f-tests/HID
git clone --depth 1 -b lollipop-release https://android.googlesource.com/platform/system/core
cd ../NFC; make
popd

git clone --depth 1 https://github.com/canokeys/fido2-tests.git
pushd fido2-tests
pip3 install --user -r requirements.txt
popd
