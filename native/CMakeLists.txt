# SPDX-License-Identifier: Apache-2.0
if(CANOKEY_APPLET_ADMIN OR CANOKEY_APPLET_PASS OR CANOKEY_APPLET_OATH OR
   CANOKEY_APPLET_OPENPGP OR CANOKEY_APPLET_PIV OR CANOKEY_APPLET_CTAP OR CANOKEY_APPLET_NDEF)
  find_package(OpenSSL REQUIRED)
  add_library(card-crypto STATIC ${CANOKEY_ROOT}/crates/host/native/crypto.c)
  target_link_libraries(card-crypto PRIVATE OpenSSL::Crypto)
  target_include_directories(card-crypto PRIVATE ${CANOKEY_ROOT}/native/support/include ${CANOKEY_ROOT}/crates/ffi/include ${CANOKEY_ROOT}/crates/native-crypto/include)
  target_compile_options(card-crypto PRIVATE -Wall -Wextra -Werror -UNDEBUG)
  if(CANOKEY_APDU_REPLAY AND CANOKEY_HOST_SANITIZERS)
    target_compile_options(card-crypto PRIVATE -fno-omit-frame-pointer -fsanitize=address,undefined)
  endif()
endif()
if(CANOKEY_APPLET_OPENPGP OR CANOKEY_APPLET_PIV OR CANOKEY_APPLET_CTAP)
  find_package(OpenSSL REQUIRED)
  set(USE_MBEDCRYPTO ON CACHE BOOL "" FORCE)
  if(NOT TARGET canokey-crypto)
    add_subdirectory("${CANOKEY_ROOT}/third_party/canokey-crypto" "${CMAKE_CURRENT_BINARY_DIR}/crypto")
  endif()
  # Exercise the production adapters against host crypto primitives.
  add_library(host-key-services STATIC ${CANOKEY_ROOT}/native/crypto/key_crypto.c ${CANOKEY_ROOT}/native/crypto/digest_crypto.c)
  target_link_libraries(host-key-services PUBLIC canokey-crypto)
  target_include_directories(host-key-services PUBLIC "${CANOKEY_ROOT}/native/support/include" "${CANOKEY_ROOT}/crates/ffi/include" "${CANOKEY_ROOT}/crates/native-crypto/include")
  target_compile_definitions(host-key-services PUBLIC
    $<$<BOOL:${CANOKEY_APPLET_OPENPGP}>:RUST_CORE_OPENPGP>
    $<$<BOOL:${CANOKEY_APPLET_CTAP}>:RUST_CORE_CTAP>
    $<$<BOOL:${CANOKEY_APPLET_PIV}>:RUST_CORE_PIV>)
  if(CANOKEY_APPLET_PIV OR CANOKEY_APPLET_CTAP)
    target_sources(host-key-services PRIVATE ${CANOKEY_ROOT}/native/crypto/piv_crypto.c)
  endif()
endif()
