# SPDX-License-Identifier: Apache-2.0
if(CANOKEY_APPLET_OPENPGP OR CANOKEY_APPLET_PIV OR CANOKEY_APPLET_CTAP)
  find_package(OpenSSL REQUIRED)
  set(USE_MBEDCRYPTO ON CACHE BOOL "" FORCE)
  if(NOT TARGET canokey-crypto)
    add_subdirectory("${CANOKEY_ROOT}/third_party/canokey-crypto" "${CMAKE_CURRENT_BINARY_DIR}/crypto")
  endif()
  # Exercise the production adapters against host crypto primitives.
  add_library(host-key-services STATIC ${CANOKEY_ROOT}/native/crypto/key_crypto.c ${CANOKEY_ROOT}/native/crypto/digest_crypto.c)
  target_link_libraries(host-key-services PUBLIC canokey-crypto)
  target_include_directories(host-key-services PUBLIC "${CANOKEY_ROOT}/native/include")
  target_compile_definitions(host-key-services PUBLIC
    $<$<BOOL:${CANOKEY_APPLET_OPENPGP}>:RUST_CORE_OPENPGP>
    $<$<BOOL:${CANOKEY_APPLET_CTAP}>:RUST_CORE_CTAP>
    $<$<BOOL:${CANOKEY_APPLET_PIV}>:RUST_CORE_PIV>)
  if(CANOKEY_APPLET_PIV OR CANOKEY_APPLET_CTAP)
    target_sources(host-key-services PRIVATE ${CANOKEY_ROOT}/native/crypto/piv_crypto.c)
  endif()
endif()
