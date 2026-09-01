#!/bin/bash
# Build FIDO test tools (only runs on cache miss)
set -e

if [ ! -d u2f-ref-code ]; then
  git clone --depth 1 https://github.com/google/u2f-ref-code.git
  pushd u2f-ref-code/u2f-tests/HID
  git clone --depth 1 -b lollipop-release https://android.googlesource.com/platform/system/core
  cd ../NFC; make
  cd ../HID; make
  popd
fi

if [ ! -d fido2-tests ]; then
  git clone --depth 1 -b dev-fido2v1 https://github.com/canokeys/fido2-tests.git
fi

if [ ! -d libfido2 ]; then
  git clone --depth 1 --branch 1.11.0 https://github.com/Yubico/libfido2.git
  mkdir libfido2/build
  pushd libfido2/build
  cmake -DUSE_PCSC=ON ..
  make -j2
  popd
fi
