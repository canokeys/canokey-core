# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.20)
project(canokey_rust_core_host C)
option(CANOKEY_APPLET_CTAP "Add Rust CTAP" OFF)
option(CANOKEY_APPLET_PASS "Add the Rust PASS applet" OFF)
option(CANOKEY_APPLET_OATH "Add Rust OATH" OFF)
option(CANOKEY_APPLET_OPENPGP "Add Rust OpenPGP" OFF)
option(CANOKEY_APPLET_PIV "Add Rust PIV" OFF)
if(CANOKEY_APPLET_OPENPGP)
  set(CANOKEY_APPLET_OATH ON)
endif()
if(CANOKEY_APPLET_OATH)
  set(CANOKEY_APPLET_PASS ON)
endif()
include("${CMAKE_CURRENT_SOURCE_DIR}/../cmake/ReleaseVersions.cmake")
find_program(CARGO cargo REQUIRED)
set(FEATURES host-runtime,static-backend)
if(CANOKEY_APPLET_CTAP)
  string(APPEND FEATURES ,ctap,admin)
endif()
if(CANOKEY_APPLET_PIV)
  string(APPEND FEATURES ,piv)
endif()
if(CANOKEY_APPLET_PASS)
  string(APPEND FEATURES ,admin,pass)
endif()
if(CANOKEY_APPLET_OATH)
  string(APPEND FEATURES ,oath)
endif()
if(CANOKEY_APPLET_OPENPGP)
  string(APPEND FEATURES ,openpgp)
endif()
set(ARCHIVE "${CMAKE_CURRENT_BINARY_DIR}/cargo/release/libcanokey_rust_ffi.a")
# This standalone build never includes the legacy core CMake/source glob.
add_custom_target(rust-core-build ALL
  COMMAND "${CMAKE_COMMAND}" -E env "CANOKEY_OATH_VERSION=${CANOKEY_OATH_VERSION}" "CANOKEY_PIV_VERSION=${CANOKEY_PIV_VERSION}"
    ${CARGO} +nightly-2026-09-04 rustc
    --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/ffi/Cargo.toml
    --target-dir ${CMAKE_CURRENT_BINARY_DIR}/cargo
    --release --features ${FEATURES} --crate-type staticlib
  BYPRODUCTS ${ARCHIVE}
  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/ffi/Cargo.toml
          ${CMAKE_CURRENT_SOURCE_DIR}/core/Cargo.toml
          ${CMAKE_CURRENT_SOURCE_DIR}/ports/Cargo.toml
          ${CMAKE_CURRENT_SOURCE_DIR}/protocol/Cargo.toml
  VERBATIM)
add_library(canokey-rust-core STATIC IMPORTED GLOBAL)
set_target_properties(canokey-rust-core PROPERTIES IMPORTED_LOCATION "${ARCHIVE}"
  INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/../interfaces/rust-core")
add_dependencies(canokey-rust-core rust-core-build)
include(CTest)
if(BUILD_TESTING)
  add_executable(hid-usb core/tests/hid_usb.c ../interfaces/rust-core/ctaphid.c)
  foreach(transport hid-usb)
    target_include_directories(${transport} PRIVATE
      ../interfaces/rust-core ../interfaces/USB/core/inc ../interfaces/USB/device
      ../interfaces/USB/class/ccid ../interfaces/USB/class/ctaphid
      ../interfaces/NFC ../include ../littlefs ../canokey-crypto/include)
    target_compile_definitions(${transport} PRIVATE RUST_CORE_USB=1 ENABLE_IFACE_CTAPHID=1
      ENABLE_IFACE_CCID=1 ENABLE_IFACE_WEBUSB=0 ENABLE_IFACE_KBDHID=0)
    target_compile_options(${transport} PRIVATE -Wall -Wextra -UNDEBUG)
    add_test(NAME ${transport} COMMAND ${transport})
  endforeach()
  add_executable(core-normal core/tests/normal.c)
  target_compile_options(core-normal PRIVATE -Wall -Wextra -UNDEBUG)
  target_link_libraries(core-normal PRIVATE canokey-rust-core)
  if(CANOKEY_APPLET_PASS)
    find_package(OpenSSL REQUIRED)
    target_sources(core-normal PRIVATE core/tests/services.c)
    target_compile_definitions(core-normal PRIVATE WITH_PASS)
    target_link_libraries(core-normal PRIVATE OpenSSL::Crypto)
  endif()
  if(CANOKEY_APPLET_OATH)
    target_compile_definitions(core-normal PRIVATE WITH_OATH)
    add_executable(oath-host core/tests/oath_host.c core/tests/services.c)
    target_compile_definitions(oath-host PRIVATE WITH_OATH)
    target_compile_options(oath-host PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_libraries(oath-host PRIVATE canokey-rust-core OpenSSL::Crypto)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(NAME oath-normal COMMAND "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/core/tests/oath_normal.py"
      --host $<TARGET_FILE:oath-host> --expected-version "${CANOKEY_OATH_VERSION}")
    set_tests_properties(oath-normal PROPERTIES TIMEOUT 60)
  endif()
  if(CANOKEY_APPLET_OPENPGP OR CANOKEY_APPLET_PIV OR CANOKEY_APPLET_CTAP)
    find_package(OpenSSL REQUIRED)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    set(USE_MBEDCRYPTO ON CACHE BOOL "" FORCE)
    add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../canokey-crypto" "${CMAKE_CURRENT_BINARY_DIR}/crypto")
    # Exercise the production adapters against host crypto primitives.
    add_library(host-key-services STATIC ../interfaces/rust-core/key_crypto.c ../interfaces/rust-core/digest_crypto.c)
    target_link_libraries(host-key-services PUBLIC canokey-crypto)
    target_compile_definitions(host-key-services PUBLIC
      $<$<BOOL:${CANOKEY_APPLET_OPENPGP}>:RUST_CORE_OPENPGP>
      $<$<BOOL:${CANOKEY_APPLET_CTAP}>:RUST_CORE_CTAP>
      $<$<BOOL:${CANOKEY_APPLET_PIV}>:RUST_CORE_PIV>)
    add_executable(crypto-profile core/tests/crypto_profile.c)
    target_include_directories(crypto-profile PRIVATE ../interfaces/rust-core)
    target_compile_options(crypto-profile PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_libraries(crypto-profile PRIVATE host-key-services)
    add_test(NAME crypto-profile COMMAND crypto-profile)
    if(CANOKEY_APPLET_PIV OR CANOKEY_APPLET_CTAP)
      target_sources(host-key-services PRIVATE ../interfaces/rust-core/piv_crypto.c)
    endif()
    if(NOT CANOKEY_APPLET_PASS)
      target_sources(core-normal PRIVATE core/tests/services.c)
      target_link_libraries(core-normal PRIVATE OpenSSL::Crypto)
    endif()
    target_link_libraries(core-normal PRIVATE host-key-services)
    if(TARGET oath-host)
      target_link_libraries(oath-host PRIVATE host-key-services)
    endif()
  endif()
  if(CANOKEY_APPLET_CTAP)
    target_compile_definitions(core-normal PRIVATE WITH_CTAP)
    add_executable(ctap-host core/tests/oath_host.c core/tests/services.c)
    target_compile_definitions(ctap-host PRIVATE WITH_CTAP)
    target_compile_options(ctap-host PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_libraries(ctap-host PRIVATE canokey-rust-core OpenSSL::Crypto host-key-services)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(NAME ctap-normal COMMAND "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/core/tests/ctap_normal.py" --host $<TARGET_FILE:ctap-host>)
  endif()
  if(CANOKEY_APPLET_OPENPGP)
    foreach(target core-normal oath-host)
      target_compile_definitions(${target} PRIVATE WITH_OPENPGP)
    endforeach()
    add_test(NAME openpgp-normal COMMAND "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/core/tests/openpgp_normal.py" --host $<TARGET_FILE:oath-host>)
    set_tests_properties(openpgp-normal PROPERTIES TIMEOUT 300)
  endif()
  if(CANOKEY_APPLET_PIV)
    target_compile_definitions(core-normal PRIVATE WITH_PIV)
    if(TARGET oath-host)
      target_compile_definitions(oath-host PRIVATE WITH_PIV)
    endif()
    add_executable(piv-host core/tests/oath_host.c core/tests/services.c)
    target_compile_definitions(piv-host PRIVATE WITH_PIV)
    target_compile_options(piv-host PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_libraries(piv-host PRIVATE canokey-rust-core OpenSSL::Crypto host-key-services)
    add_test(NAME piv-normal COMMAND "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/core/tests/piv_normal.py" --host $<TARGET_FILE:piv-host>)
  endif()
  if(CANOKEY_APPLET_OPENPGP AND CANOKEY_APPLET_PIV)
    add_test(NAME compact-storage COMMAND "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/core/tests/compact_storage.py" $<TARGET_FILE:oath-host>)
    add_test(NAME combined-reset COMMAND "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/core/tests/reset_normal.py" --host $<TARGET_FILE:oath-host>)
  endif()
  if(CANOKEY_APPLET_CTAP)
    foreach(target oath-host openpgp-host piv-host)
      if(TARGET ${target})
        target_compile_definitions(${target} PRIVATE WITH_CTAP)
      endif()
    endforeach()
    if(CANOKEY_APPLET_CTAP)
      add_test(NAME ctap-u2f COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/core/tests/ctap_u2f.py" --host $<TARGET_FILE:ctap-host>)
      add_test(NAME ctap-config COMMAND "${Python3_EXECUTABLE}"
        "${CMAKE_CURRENT_SOURCE_DIR}/core/tests/ctap_config.py" --host $<TARGET_FILE:ctap-host>)
    endif()
  endif()
  # Platform integration uses the real Rust CCID facade and CIU packet driver.
  # This optional parent-port fixture is absent in a standalone core checkout.
  if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../tools/hil/test_rust_ccid.py")
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_test(NAME ccid-usb COMMAND "${Python3_EXECUTABLE}"
      "${CMAKE_CURRENT_SOURCE_DIR}/../../tools/hil/test_rust_ccid.py")
    set_tests_properties(ccid-usb PROPERTIES TIMEOUT 120)
  endif()
  add_test(NAME core-normal COMMAND core-normal)
  # Pure transport tests also run in profiles without the CTAP firmware applet.
  set(RUST_TEST_FEATURES canokey-rust-core/ctap)
  if(CANOKEY_APPLET_PASS)
    list(APPEND RUST_TEST_FEATURES canokey-rust-core/admin canokey-rust-core/pass)
  endif()
  if(CANOKEY_APPLET_OATH)
    list(APPEND RUST_TEST_FEATURES canokey-rust-core/oath)
  endif()
  if(CANOKEY_APPLET_OPENPGP)
    list(APPEND RUST_TEST_FEATURES canokey-rust-core/openpgp)
  endif()
  if(CANOKEY_APPLET_PIV)
    list(APPEND RUST_TEST_FEATURES canokey-rust-core/piv)
  endif()
  list(JOIN RUST_TEST_FEATURES "," RUST_TEST_FEATURES)
  add_test(NAME rust-normal COMMAND ${CARGO} +nightly-2026-09-04 test
    --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml
    --target-dir ${CMAKE_CURRENT_BINARY_DIR}/cargo-tests
    -p canokey-protocol -p canokey-rust-core --features "${RUST_TEST_FEATURES}")
  set_tests_properties(rust-normal PROPERTIES TIMEOUT 120)
endif()
