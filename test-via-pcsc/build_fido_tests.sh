#!/bin/bash
set -e
if [ ! -d u2f-ref-code ];then
git clone --depth 1 https://github.com/google/u2f-ref-code.git
pushd u2f-ref-code/u2f-tests/HID
git clone --depth 1 -b lollipop-release https://android.googlesource.com/platform/system/core
cd ../NFC; make
cd ../HID; make
popd
fi

git clone --depth 1 -b dev-fido2v1 https://github.com/canokeys/fido2-tests.git
pushd fido2-tests
pip3 install --user -r requirements.txt
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
