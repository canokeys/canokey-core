# SPDX-License-Identifier: Apache-2.0
set(CANOKEY_PLATFORM_STORAGE_FIXTURE "" CACHE FILEPATH "Explicit platform LittleFS capacity fixture")
set(CANOKEY_PLATFORM_STORAGE_STUBS "" CACHE PATH "Platform headers for the capacity fixture")
if(CANOKEY_PLATFORM_STORAGE_FIXTURE)
  if(NOT BUILD_TESTING OR NOT CANOKEY_APPLET_OPENPGP OR NOT CANOKEY_APPLET_PIV OR
     NOT CANOKEY_APPLET_ADMIN OR NOT CANOKEY_APPLET_PASS OR NOT CANOKEY_APPLET_OATH OR
     NOT CANOKEY_APPLET_CTAP OR NOT CANOKEY_APPLET_NDEF)
    message(FATAL_ERROR "The platform storage fixture requires BUILD_TESTING and the full applet profile")
  endif()
  if(NOT EXISTS "${CANOKEY_PLATFORM_STORAGE_FIXTURE}" OR
     NOT IS_DIRECTORY "${CANOKEY_PLATFORM_STORAGE_STUBS}")
    message(FATAL_ERROR "Explicit platform storage fixture or stub directory is missing")
  endif()
endif()
if(BUILD_TESTING AND CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  # The retained native SM3 fallback must pass with fatal sanitizer diagnostics.
  add_executable(native-sm3
    ${CANOKEY_ROOT}/third_party/canokey-crypto/test/sm3_correctness.c
    ${CANOKEY_ROOT}/third_party/canokey-crypto/src/sm3.c ${CANOKEY_ROOT}/third_party/canokey-crypto/src/memzero.c)
  target_include_directories(native-sm3 PRIVATE ${CANOKEY_ROOT}/third_party/canokey-crypto/include)
  target_compile_definitions(native-sm3 PRIVATE USE_MBEDCRYPTO)
  target_compile_options(native-sm3 PRIVATE -fsanitize=undefined -fno-sanitize-recover=all)
  target_link_options(native-sm3 PRIVATE -fsanitize=undefined -fno-sanitize-recover=all)
  add_test(NAME native-sm3 COMMAND native-sm3)
  add_executable(native-keccak-bytes
    ${CANOKEY_ROOT}/third_party/canokey-crypto/test/keccak_bytes_correctness.c
    ${CANOKEY_ROOT}/third_party/canokey-crypto/src/keccak_p1600.c)
  target_compile_options(native-keccak-bytes PRIVATE -fsanitize=undefined -fno-sanitize-recover=all)
  target_link_options(native-keccak-bytes PRIVATE -fsanitize=undefined -fno-sanitize-recover=all)
  add_test(NAME native-keccak-bytes COMMAND native-keccak-bytes)
endif()

if(BUILD_TESTING)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  if(CANOKEY_APPLET_ADMIN OR CANOKEY_APPLET_PASS OR CANOKEY_APPLET_OATH OR
     CANOKEY_APPLET_OPENPGP OR CANOKEY_APPLET_PIV OR CANOKEY_APPLET_CTAP OR CANOKEY_APPLET_NDEF)
    find_package(OpenSSL REQUIRED)
  endif()
  add_executable(core-abi ${CANOKEY_ROOT}/tests/native/core_abi.c)
  target_compile_options(core-abi PRIVATE -Wall -Wextra -Werror -UNDEBUG)
  target_link_libraries(core-abi PRIVATE canokey-rust-core)
  foreach(applet ADMIN PASS OATH OPENPGP PIV CTAP NDEF)
    target_compile_definitions(core-abi PRIVATE $<$<BOOL:${CANOKEY_APPLET_${applet}}>:WITH_${applet}>)
  endforeach()
  if(CANOKEY_APPLET_ADMIN OR CANOKEY_APPLET_PASS OR CANOKEY_APPLET_OATH OR CANOKEY_APPLET_OPENPGP OR CANOKEY_APPLET_PIV OR CANOKEY_APPLET_CTAP OR CANOKEY_APPLET_NDEF)
    target_sources(core-abi PRIVATE ${CANOKEY_ROOT}/tests/support/services.c)
    target_link_libraries(core-abi PRIVATE OpenSSL::Crypto)
  endif()
  if(CANOKEY_APPLET_OATH OR CANOKEY_APPLET_OPENPGP)
    add_rust_card(oath-host FALSE)
    set(oath_profile_args "")
    if(NOT CANOKEY_APPLET_ADMIN OR NOT CANOKEY_APPLET_PASS)
      list(APPEND oath_profile_args --standalone)
    endif()
    if(CANOKEY_APPLET_OATH)
      add_test(NAME oath-normal COMMAND "${Python3_EXECUTABLE}"
        "${CANOKEY_ROOT}/tests/integration/oath_normal.py"
        --host $<TARGET_FILE:oath-host-image> --expected-version "${CANOKEY_OATH_VERSION}" ${oath_profile_args})
      set_tests_properties(oath-normal PROPERTIES TIMEOUT 60)
    endif()
  endif()
  if(CANOKEY_APPLET_OPENPGP OR CANOKEY_APPLET_PIV OR CANOKEY_APPLET_CTAP)
    add_executable(crypto-profile ${CANOKEY_ROOT}/tests/native/crypto_profile.c)
    target_include_directories(crypto-profile PRIVATE ${CANOKEY_ROOT}/native/include)
    target_compile_options(crypto-profile PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_libraries(crypto-profile PRIVATE host-key-services)
    add_test(NAME crypto-profile COMMAND crypto-profile)
    if(CANOKEY_APPLET_PIV OR CANOKEY_APPLET_CTAP)
      add_executable(stream-crypto ${CANOKEY_ROOT}/tests/native/stream_crypto.c)
      target_include_directories(stream-crypto PRIVATE ${CANOKEY_ROOT}/native/include)
      target_compile_options(stream-crypto PRIVATE -Wall -Wextra -Werror -UNDEBUG)
      target_link_libraries(stream-crypto PRIVATE host-key-services)
      add_test(NAME stream-crypto COMMAND stream-crypto)
    endif()
    target_link_libraries(core-abi PRIVATE host-key-services)
  endif()
  if(CANOKEY_APPLET_CTAP)
    # Exercise the real applet, HID framing, execution policy and mailbox in
    # one process. Only packet hardware, time and scratch memory are mocked.
    # APDU-only adapters deliberately have no USB callbacks: keep this feature
    # in a separate archive so their stubs cannot replace real HID execution.
    add_rust_host_archive(canokey-rust-hid rust-hid-build cargo-hid "${FEATURES},usb-hid")
    add_executable(hid-core ${CANOKEY_ROOT}/tests/support/hid_core.c ${CANOKEY_ROOT}/tests/support/services.c)
    target_compile_definitions(hid-core PRIVATE WITH_CTAP WITH_HID ENABLE_IFACE_CTAPHID=1)
    target_compile_options(hid-core PRIVATE -Wall -Wextra -Werror -UNDEBUG)
    target_link_libraries(hid-core PRIVATE canokey-rust-hid OpenSSL::Crypto host-key-services)
    add_test(NAME hid-core COMMAND hid-core)
    set_tests_properties(hid-core PROPERTIES TIMEOUT 30)
    if(CANOKEY_APPLET_PASS)
      add_rust_host_archive(canokey-rust-usb rust-usb-build cargo-usb
        "${FEATURES},usb-hid,usb-device,usb-webusb,usb-keyboard")
      add_executable(usb-sessions ${CANOKEY_ROOT}/tests/support/usb_sessions.c ${CANOKEY_ROOT}/tests/support/services.c)
      target_compile_definitions(usb-sessions PRIVATE WITH_CTAP WITH_HID ENABLE_IFACE_CTAPHID=1)
      target_compile_definitions(usb-sessions PRIVATE
        $<$<BOOL:${CANOKEY_APPLET_OPENPGP}>:WITH_OPENPGP>
        $<$<BOOL:${CANOKEY_APPLET_PIV}>:WITH_PIV>)
      target_compile_options(usb-sessions PRIVATE -Wall -Wextra -Werror -UNDEBUG)
      target_link_libraries(usb-sessions PRIVATE canokey-rust-usb OpenSSL::Crypto host-key-services)
      add_test(NAME usb-sessions COMMAND usb-sessions)
      set_tests_properties(usb-sessions PROPERTIES TIMEOUT 30)
    endif()
    add_rust_card(ctap-host FALSE)
    # Same fixture and native crypto, independently compiled algorithm policy.
    add_rust_card(ctap-restricted-host TRUE)
    if(CANOKEY_APPLET_ADMIN)
    add_test(NAME ctap-normal COMMAND "${Python3_EXECUTABLE}"
      "${CANOKEY_ROOT}/tests/integration/ctap_normal.py" --host $<TARGET_FILE:ctap-host-image>
      --restricted-host $<TARGET_FILE:ctap-restricted-host-image>)
    endif()
  endif()
  if(CANOKEY_APPLET_OPENPGP)
    set(openpgp_profile_args "")
    if(NOT CANOKEY_APPLET_ADMIN)
      list(APPEND openpgp_profile_args --standalone)
    endif()
    add_test(NAME openpgp-normal COMMAND "${Python3_EXECUTABLE}"
      "${CANOKEY_ROOT}/tests/integration/openpgp_normal.py" --host $<TARGET_FILE:oath-host-image> ${openpgp_profile_args})
    set_tests_properties(openpgp-normal PROPERTIES TIMEOUT 300)
  endif()
  if(CANOKEY_APPLET_PIV)
    add_rust_card(piv-host FALSE)
    add_test(NAME piv-normal COMMAND "${Python3_EXECUTABLE}"
      "${CANOKEY_ROOT}/tests/integration/piv_normal.py" --host $<TARGET_FILE:piv-host-image>)
  endif()
  if(CANOKEY_APPLET_OPENPGP AND CANOKEY_APPLET_PIV AND CANOKEY_APPLET_ADMIN AND CANOKEY_APPLET_PASS AND CANOKEY_APPLET_OATH)
    if(CANOKEY_PLATFORM_STORAGE_FIXTURE)
      add_executable(storage-applet-host ${CANOKEY_ROOT}/tests/support/oath_host.c
        ${CANOKEY_ROOT}/tests/support/services.c ${CANOKEY_PLATFORM_STORAGE_FIXTURE}
        ${CANOKEY_ROOT}/third_party/littlefs/lfs.c ${CANOKEY_ROOT}/third_party/littlefs/lfs_util.c)
      target_compile_definitions(storage-applet-host PRIVATE CK_TEST_LITTLEFS WITH_ADMIN WITH_PASS WITH_OATH
        WITH_OPENPGP WITH_PIV WITH_CTAP WITH_NDEF LFS_NO_MALLOC LFS_NO_DEBUG LFS_NO_WARN LFS_NO_ERROR)
      target_include_directories(storage-applet-host PRIVATE ${CANOKEY_PLATFORM_STORAGE_STUBS}
        ${CANOKEY_ROOT}/third_party/littlefs)
      target_compile_options(storage-applet-host PRIVATE -Wall -Wextra -UNDEBUG)
      target_link_libraries(storage-applet-host PRIVATE canokey-rust-core OpenSSL::Crypto host-key-services)
    endif()
    add_test(NAME compact-storage COMMAND "${Python3_EXECUTABLE}"
      "${CANOKEY_ROOT}/tests/integration/compact_storage.py" $<TARGET_FILE:oath-host-image>)
    add_test(NAME combined-reset COMMAND "${Python3_EXECUTABLE}"
      "${CANOKEY_ROOT}/tests/integration/reset_normal.py" --host $<TARGET_FILE:oath-host-image>)
  endif()
  if(CANOKEY_APPLET_CTAP)
    if(CANOKEY_APPLET_ADMIN)
      add_test(NAME ctap-u2f COMMAND "${Python3_EXECUTABLE}"
        "${CANOKEY_ROOT}/tests/integration/ctap_u2f.py" --host $<TARGET_FILE:ctap-host-image>)
      add_test(NAME ctap-config COMMAND "${Python3_EXECUTABLE}"
        "${CANOKEY_ROOT}/tests/integration/ctap_config.py" --host $<TARGET_FILE:ctap-host-image>)
    endif()
  endif()
  add_test(NAME core-abi COMMAND core-abi)
  add_rust_card(core-behavior FALSE core-behavior)
  add_test(NAME core-behavior COMMAND $<TARGET_FILE:core-behavior-image>)
  add_rust_card(runtime-composition FALSE runtime-composition)
  add_test(NAME runtime-composition COMMAND $<TARGET_FILE:runtime-composition-image>)
  # Pure transport tests also run in profiles without the CTAP firmware applet.
  set(RUST_TEST_FEATURES canokey-rust-core/ctap)
  if(CTAP_RESTRICT_ALGORITHMS)
    list(APPEND RUST_TEST_FEATURES canokey-rust-core/ctap-restrict-algorithms)
  endif()
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
  if(CANOKEY_APPLET_NDEF)
    list(APPEND RUST_TEST_FEATURES canokey-rust-core/ndef)
  endif()
  list(JOIN RUST_TEST_FEATURES "," RUST_TEST_FEATURES)
  add_test(NAME rust-normal COMMAND ${CARGO} +${CANOKEY_RUST_TOOLCHAIN} test
    --manifest-path ${CANOKEY_ROOT}/Cargo.toml
    --target-dir ${CMAKE_CURRENT_BINARY_DIR}/cargo-tests
    -p canokey-protocol -p canokey-rust-core --features "${RUST_TEST_FEATURES}")
  set_tests_properties(rust-normal PROPERTIES TIMEOUT 120)
endif()


if(ENABLE_TESTS)
  add_subdirectory(native)
endif()
get_property(correctness_tests DIRECTORY PROPERTY TESTS)
if(correctness_tests)
  set_property(TEST ${correctness_tests} APPEND PROPERTY ENVIRONMENT "UBSAN_OPTIONS=halt_on_error=1")
endif()
