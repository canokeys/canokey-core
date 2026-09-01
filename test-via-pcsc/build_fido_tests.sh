#!/bin/bash
# Build FIDO test tools (only runs on cache miss)
set -e

readonly FIDO2_TESTS_REF=f92e8d9a7692b4a540f05f9e63b269661d667876

if [ ! -d u2f-ref-code ]; then
  git clone --depth 1 https://github.com/google/u2f-ref-code.git
  pushd u2f-ref-code/u2f-tests/HID
  git clone --depth 1 -b lollipop-release https://android.googlesource.com/platform/system/core
  cd ../NFC; make
  cd ../HID; make
  popd
fi

if [ ! -d fido2-tests ]; then
  git clone https://github.com/canokeys/fido2-tests.git
  git -C fido2-tests checkout "${FIDO2_TESTS_REF}"
fi

if [ ! -d libfido2 ]; then
  git clone --depth 1 --branch 1.11.0 https://github.com/Yubico/libfido2.git
  mkdir libfido2/build
  pushd libfido2/build
  cmake -DUSE_PCSC=ON ..
  make -j2
  popd
fi
