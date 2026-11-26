# SPDX-License-Identifier: Apache-2.0
set(CANOKEY_PLATFORM_STORAGE_FIXTURE "" CACHE FILEPATH "Explicit platform LittleFS capacity fixture")
set(CANOKEY_PLATFORM_STORAGE_STUBS "" CACHE PATH "Platform headers for the capacity fixture")
set(CANOKEY_PLATFORM_STORAGE_MANIFEST "" CACHE FILEPATH "Rust platform storage transaction manifest")
if(CANOKEY_PLATFORM_STORAGE_FIXTURE)
  if(NOT BUILD_TESTING OR NOT CANOKEY_APPLET_OPENPGP OR NOT CANOKEY_APPLET_PIV OR
     NOT CANOKEY_APPLET_ADMIN OR NOT CANOKEY_APPLET_PASS OR NOT CANOKEY_APPLET_OATH OR
     NOT CANOKEY_APPLET_CTAP OR NOT CANOKEY_APPLET_NDEF)
    message(FATAL_ERROR "The platform storage fixture requires BUILD_TESTING and the full applet profile")
  endif()
  if(NOT EXISTS "${CANOKEY_PLATFORM_STORAGE_FIXTURE}" OR
     NOT IS_DIRECTORY "${CANOKEY_PLATFORM_STORAGE_STUBS}" OR
     NOT EXISTS "${CANOKEY_PLATFORM_STORAGE_MANIFEST}")
    message(FATAL_ERROR "Explicit platform storage fixture, stub directory or Rust manifest is missing")
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
    set(fixture_features platform-key)
    if(CANOKEY_APPLET_CTAP)
      list(APPEND fixture_features ctap)
    endif()
    if(CANOKEY_APPLET_PIV)
      list(APPEND fixture_features piv)
    endif()
    if(CANOKEY_APPLET_OPENPGP)
      list(APPEND fixture_features platform-rsa platform-x25519)
    endif()
    list(JOIN fixture_features "," fixture_features)
    set(crypto_fixture "${CMAKE_CURRENT_BINARY_DIR}/cargo-crypto-fixture/release/examples/libcrypto_fixture.a")
    add_custom_target(build-crypto-fixture
      COMMAND ${CARGO} +${CANOKEY_RUST_TOOLCHAIN} build --manifest-path "${CANOKEY_ROOT}/Cargo.toml"
        -p canokey-native-crypto --release --example crypto-fixture --features "${fixture_features}"
        --target-dir "${CMAKE_CURRENT_BINARY_DIR}/cargo-crypto-fixture"
      BYPRODUCTS "${crypto_fixture}" VERBATIM)
    find_package(Threads REQUIRED)
    add_executable(crypto-profile ${CANOKEY_ROOT}/tests/native/crypto_profile.c)
    add_dependencies(crypto-profile build-crypto-fixture)
    target_include_directories(crypto-profile PRIVATE ${CANOKEY_ROOT}/crates/native-crypto/include)
    target_compile_options(crypto-profile PRIVATE -Wall -Wextra -UNDEBUG)
    target_link_libraries(crypto-profile PRIVATE "${crypto_fixture}" host-key-services Threads::Threads ${CMAKE_DL_LIBS} m)
    add_test(NAME crypto-profile COMMAND crypto-profile)
    if(CANOKEY_APPLET_PIV OR CANOKEY_APPLET_CTAP)
      add_executable(stream-crypto ${CANOKEY_ROOT}/tests/native/stream_crypto.c)
      target_include_directories(stream-crypto PRIVATE ${CANOKEY_ROOT}/crates/native-crypto/include)
      target_compile_options(stream-crypto PRIVATE -Wall -Wextra -Werror -UNDEBUG)
      add_dependencies(stream-crypto build-crypto-fixture)
      target_link_libraries(stream-crypto PRIVATE "${crypto_fixture}" host-key-services Threads::Threads ${CMAKE_DL_LIBS} m)
      add_test(NAME stream-crypto COMMAND stream-crypto)
      add_executable(pq-stream ${CANOKEY_ROOT}/tests/native/pq_stream.c)
      target_include_directories(pq-stream PRIVATE ${CANOKEY_ROOT}/crates/native-crypto/include)
      target_compile_options(pq-stream PRIVATE -Wall -Wextra -Werror -UNDEBUG)
      add_dependencies(pq-stream build-crypto-fixture)
      target_link_libraries(pq-stream PRIVATE "${crypto_fixture}" host-key-services Threads::Threads ${CMAKE_DL_LIBS} m)
      add_test(NAME pq-stream COMMAND pq-stream)
    endif()
  endif()
  if(CANOKEY_APPLET_CTAP)
    # Exercise the real applet, HID framing, execution policy and mailbox in
    # one process. Only packet hardware, time and scratch memory are mocked.
    # APDU-only adapters deliberately have no USB callbacks: keep this feature
    # in a separate archive so their stubs cannot replace real HID execution.
    add_rust_card(hid-core FALSE hid-core-rust)
    add_test(NAME hid-core COMMAND $<TARGET_FILE:hid-core-image>)
    set_tests_properties(hid-core PROPERTIES TIMEOUT 30)
    if(CANOKEY_APPLET_PASS)
      add_rust_card(usb-sessions FALSE usb-sessions-rust)
      add_test(NAME usb-sessions COMMAND $<TARGET_FILE:usb-sessions-image>)
      set_tests_properties(usb-sessions PROPERTIES TIMEOUT 30)
      add_test(NAME ccid-wire COMMAND "${Python3_EXECUTABLE}"
        "${CANOKEY_ROOT}/tests/support/wire_replay.py"
        --rust-runner $<TARGET_FILE:usb-sessions-image>
        --vectors "${CANOKEY_ROOT}/tests/fixtures/ccid/vectors.json"
        --output "${CMAKE_CURRENT_BINARY_DIR}/ccid-rust.json")
      set_tests_properties(ccid-wire PROPERTIES TIMEOUT 45)
      add_test(NAME webusb-wire COMMAND "${Python3_EXECUTABLE}"
        "${CANOKEY_ROOT}/tests/support/wire_replay.py"
        --rust-runner $<TARGET_FILE:usb-sessions-image>
        --vectors "${CANOKEY_ROOT}/tests/fixtures/webusb/vectors.json"
        --output "${CMAKE_CURRENT_BINARY_DIR}/webusb-rust.json")
      set_tests_properties(webusb-wire PROPERTIES TIMEOUT 45)
      add_test(NAME usb-control-wire COMMAND "${Python3_EXECUTABLE}"
        "${CANOKEY_ROOT}/tests/support/wire_replay.py"
        --rust-runner $<TARGET_FILE:usb-sessions-image>
        --vectors "${CANOKEY_ROOT}/tests/fixtures/usb-control/vectors.json"
        --output "${CMAKE_CURRENT_BINARY_DIR}/usb-control-rust.json")
      set_tests_properties(usb-control-wire PROPERTIES TIMEOUT 45)
      add_test(NAME usb-lifecycle-wire COMMAND "${Python3_EXECUTABLE}"
        "${CANOKEY_ROOT}/tests/support/wire_replay.py"
        --rust-runner $<TARGET_FILE:usb-sessions-image>
        --vectors "${CANOKEY_ROOT}/tests/fixtures/usb-lifecycle/vectors.json"
        --output "${CMAKE_CURRENT_BINARY_DIR}/usb-lifecycle-rust.json")
      set_tests_properties(usb-lifecycle-wire PROPERTIES TIMEOUT 45)
      add_test(NAME usb-readiness-wire COMMAND "${Python3_EXECUTABLE}"
        "${CANOKEY_ROOT}/tests/support/wire_replay.py"
        --rust-runner $<TARGET_FILE:usb-sessions-image>
        --vectors "${CANOKEY_ROOT}/tests/fixtures/usb-readiness/vectors.json"
        --output "${CMAKE_CURRENT_BINARY_DIR}/usb-readiness-rust.json")
      set_tests_properties(usb-readiness-wire PROPERTIES TIMEOUT 45)
      add_test(NAME webusb-readiness-wire COMMAND "${Python3_EXECUTABLE}"
        "${CANOKEY_ROOT}/tests/support/wire_replay.py"
        --rust-runner $<TARGET_FILE:usb-sessions-image>
        --vectors "${CANOKEY_ROOT}/tests/fixtures/webusb-readiness/vectors.json"
        --output "${CMAKE_CURRENT_BINARY_DIR}/webusb-readiness-rust.json")
      set_tests_properties(webusb-readiness-wire PROPERTIES TIMEOUT 45)
      add_test(NAME webusb-retained-wire COMMAND "${Python3_EXECUTABLE}"
        "${CANOKEY_ROOT}/tests/support/wire_replay.py"
        --rust-runner $<TARGET_FILE:usb-sessions-image>
        --vectors "${CANOKEY_ROOT}/tests/fixtures/webusb-retained/vectors.json"
        --output "${CMAKE_CURRENT_BINARY_DIR}/webusb-retained-rust.json")
      set_tests_properties(webusb-retained-wire PROPERTIES TIMEOUT 45)
      add_test(NAME usb-ownership-wire COMMAND "${Python3_EXECUTABLE}"
        "${CANOKEY_ROOT}/tests/support/wire_replay.py"
        --rust-runner $<TARGET_FILE:usb-sessions-image>
        --vectors "${CANOKEY_ROOT}/tests/fixtures/usb-ownership/vectors.json"
        --output "${CMAKE_CURRENT_BINARY_DIR}/usb-ownership-rust.json")
      set_tests_properties(usb-ownership-wire PROPERTIES TIMEOUT 45)
      add_test(NAME hid-ownership-wire COMMAND "${Python3_EXECUTABLE}"
        "${CANOKEY_ROOT}/tests/support/wire_replay.py"
        --rust-runner $<TARGET_FILE:usb-sessions-image>
        --vectors "${CANOKEY_ROOT}/tests/fixtures/hid-ownership/vectors.json"
        --output "${CMAKE_CURRENT_BINARY_DIR}/hid-ownership-rust.json")
      set_tests_properties(hid-ownership-wire PROPERTIES TIMEOUT 45)
      add_test(NAME hid-admission-wire COMMAND "${Python3_EXECUTABLE}"
        "${CANOKEY_ROOT}/tests/support/wire_replay.py"
        --rust-runner $<TARGET_FILE:usb-sessions-image>
        --vectors "${CANOKEY_ROOT}/tests/fixtures/hid-admission/vectors.json"
        --output "${CMAKE_CURRENT_BINARY_DIR}/hid-admission-rust.json")
      set_tests_properties(hid-admission-wire PROPERTIES TIMEOUT 45)
      add_test(NAME hid-channels-wire COMMAND "${Python3_EXECUTABLE}"
        "${CANOKEY_ROOT}/tests/support/wire_replay.py"
        --rust-runner $<TARGET_FILE:usb-sessions-image>
        --vectors "${CANOKEY_ROOT}/tests/fixtures/hid-channels/vectors.json"
        --output "${CMAKE_CURRENT_BINARY_DIR}/hid-channels-rust.json")
      set_tests_properties(hid-channels-wire PROPERTIES TIMEOUT 45)
      add_test(NAME large-blob-usb-wire COMMAND "${Python3_EXECUTABLE}"
        "${CANOKEY_ROOT}/tests/support/wire_replay.py"
        --rust-runner $<TARGET_FILE:usb-sessions-image>
        --vectors "${CANOKEY_ROOT}/tests/fixtures/large-blob-usb/vectors.json"
        --output "${CMAKE_CURRENT_BINARY_DIR}/large-blob-usb-rust.json")
      set_tests_properties(large-blob-usb-wire PROPERTIES TIMEOUT 45)
      if(CANOKEY_APPLET_NDEF AND CANOKEY_APPLET_OPENPGP)
        add_rust_card(nfc-wire FALSE usb-sessions-rust)
        add_test(NAME nfc-source-faults COMMAND $<TARGET_FILE:nfc-wire-image> --nfc-source-faults)
        set_tests_properties(nfc-source-faults PROPERTIES TIMEOUT 30)
        add_test(NAME nfc-wire COMMAND "${Python3_EXECUTABLE}"
          "${CANOKEY_ROOT}/tests/support/wire_replay.py"
          --rust-runner $<TARGET_FILE:nfc-wire-image>
          --vectors "${CANOKEY_ROOT}/tests/fixtures/nfc/vectors.json"
          --output "${CMAKE_CURRENT_BINARY_DIR}/nfc-rust.json")
        set_tests_properties(nfc-wire PROPERTIES TIMEOUT 45)
        add_test(NAME nfc-execution COMMAND "${Python3_EXECUTABLE}"
          "${CANOKEY_ROOT}/tests/support/nfc_execution.py"
          --rust-runner $<TARGET_FILE:nfc-wire-image>
          --output "${CMAKE_CURRENT_BINARY_DIR}/nfc-execution-rust.json")
        set_tests_properties(nfc-execution PROPERTIES TIMEOUT 45)
        add_test(NAME large-blob-nfc-wire COMMAND "${Python3_EXECUTABLE}"
          "${CANOKEY_ROOT}/tests/support/wire_replay.py"
          --rust-runner $<TARGET_FILE:nfc-wire-image>
          --vectors "${CANOKEY_ROOT}/tests/fixtures/large-blob-nfc/vectors.json"
          --output "${CMAKE_CURRENT_BINARY_DIR}/large-blob-nfc-rust.json")
        set_tests_properties(large-blob-nfc-wire PROPERTIES TIMEOUT 45)
        if(CANOKEY_APPLET_ADMIN)
          add_test(NAME select-wire COMMAND "${Python3_EXECUTABLE}"
            "${CANOKEY_ROOT}/tests/support/wire_replay.py"
            --rust-runner $<TARGET_FILE:nfc-wire-image>
            --vectors "${CANOKEY_ROOT}/tests/fixtures/select/vectors.json"
            --output "${CMAKE_CURRENT_BINARY_DIR}/select-rust.json")
          set_tests_properties(select-wire PROPERTIES TIMEOUT 120)
          if(CANOKEY_APPLET_PIV)
            add_test(NAME select-config-wire COMMAND "${Python3_EXECUTABLE}"
              "${CANOKEY_ROOT}/tests/support/wire_replay.py"
              --rust-runner $<TARGET_FILE:nfc-wire-image>
              --vectors "${CANOKEY_ROOT}/tests/fixtures/select-config/vectors.json"
              --output "${CMAKE_CURRENT_BINARY_DIR}/select-config-rust.json")
            set_tests_properties(select-config-wire PROPERTIES TIMEOUT 120)
            add_test(NAME select-header-wire COMMAND "${Python3_EXECUTABLE}"
              "${CANOKEY_ROOT}/tests/support/wire_replay.py"
              --rust-runner $<TARGET_FILE:nfc-wire-image>
              --vectors "${CANOKEY_ROOT}/tests/fixtures/select-header/vectors.json"
              --output "${CMAKE_CURRENT_BINARY_DIR}/select-header-rust.json")
            set_tests_properties(select-header-wire PROPERTIES TIMEOUT 120)
            add_test(NAME chain-control-wire COMMAND "${Python3_EXECUTABLE}"
              "${CANOKEY_ROOT}/tests/support/wire_replay.py"
              --rust-runner $<TARGET_FILE:nfc-wire-image>
              --vectors "${CANOKEY_ROOT}/tests/fixtures/chain-control/vectors.json"
              --output "${CMAKE_CURRENT_BINARY_DIR}/chain-control-rust.json")
            set_tests_properties(chain-control-wire PROPERTIES TIMEOUT 120)
            add_test(NAME chain-encoding-wire COMMAND "${Python3_EXECUTABLE}"
              "${CANOKEY_ROOT}/tests/support/wire_replay.py"
              --rust-runner $<TARGET_FILE:nfc-wire-image>
              --vectors "${CANOKEY_ROOT}/tests/fixtures/chain-encoding/vectors.json"
              --output "${CMAKE_CURRENT_BINARY_DIR}/chain-encoding-rust.json")
            set_tests_properties(chain-encoding-wire PROPERTIES TIMEOUT 120)
            add_test(NAME nfc-rejection-wire COMMAND "${Python3_EXECUTABLE}"
              "${CANOKEY_ROOT}/tests/support/wire_replay.py"
              --rust-runner $<TARGET_FILE:nfc-wire-image>
              --vectors "${CANOKEY_ROOT}/tests/fixtures/nfc-rejection/vectors.json"
              --output "${CMAKE_CURRENT_BINARY_DIR}/nfc-rejection-rust.json")
            set_tests_properties(nfc-rejection-wire PROPERTIES TIMEOUT 120)
            add_test(NAME nfc-inline-wire COMMAND "${Python3_EXECUTABLE}"
              "${CANOKEY_ROOT}/tests/support/wire_replay.py"
              --rust-runner $<TARGET_FILE:nfc-wire-image>
              --vectors "${CANOKEY_ROOT}/tests/fixtures/nfc-inline/vectors.json"
              --output "${CMAKE_CURRENT_BINARY_DIR}/nfc-inline-rust.json")
            set_tests_properties(nfc-inline-wire PROPERTIES TIMEOUT 120)
          endif()
          add_test(NAME auth-response-wire COMMAND "${Python3_EXECUTABLE}"
            "${CANOKEY_ROOT}/tests/support/auth_response.py"
            --rust-runner $<TARGET_FILE:nfc-wire-image>
            --transport ccid --transport webusb --transport msg --transport nfc
            --output "${CMAKE_CURRENT_BINARY_DIR}/auth-response-rust.json")
          set_tests_properties(auth-response-wire PROPERTIES TIMEOUT 120)
          add_test(NAME storage-response-wire COMMAND "${Python3_EXECUTABLE}"
            "${CANOKEY_ROOT}/tests/support/storage_faults.py"
            --rust-runner $<TARGET_FILE:nfc-wire-image>
            --output "${CMAKE_CURRENT_BINARY_DIR}/storage-response-rust.json")
          set_tests_properties(storage-response-wire PROPERTIES TIMEOUT 120)
          add_test(NAME storage-response-nfc-extended COMMAND "${Python3_EXECUTABLE}"
            "${CANOKEY_ROOT}/tests/support/storage_faults.py"
            --rust-runner $<TARGET_FILE:nfc-wire-image>
            --transport nfc --nfc-extended
            --output "${CMAKE_CURRENT_BINARY_DIR}/storage-response-nfc-extended.json")
          set_tests_properties(storage-response-nfc-extended PROPERTIES TIMEOUT 120)
          if(CANOKEY_APPLET_PIV)
            add_test(NAME session-yield-wire COMMAND "${Python3_EXECUTABLE}"
              "${CANOKEY_ROOT}/tests/support/session_yield.py"
              --rust-runner $<TARGET_FILE:nfc-wire-image>
              --output "${CMAKE_CURRENT_BINARY_DIR}/session-yield-rust.json")
            set_tests_properties(session-yield-wire PROPERTIES TIMEOUT 120)
          endif()
        endif()
      endif()
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
      if(CANOKEY_PLATFORM_STORAGE_MANIFEST)
        set(storage_bridge "${CMAKE_CURRENT_BINARY_DIR}/platform-storage/release/examples/libfixture.a")
        add_custom_target(platform-storage-bridge
          COMMAND ${CARGO} +${CANOKEY_RUST_TOOLCHAIN} build
            --manifest-path "${CANOKEY_PLATFORM_STORAGE_MANIFEST}"
            --target-dir "${CMAKE_CURRENT_BINARY_DIR}/platform-storage"
            --release --example fixture --features applet-fixture
          BYPRODUCTS "${storage_bridge}" VERBATIM)
      endif()
      add_library(storage-fixture-native STATIC
        ${CANOKEY_ROOT}/tests/support/services.c ${CANOKEY_PLATFORM_STORAGE_FIXTURE}
        ${CANOKEY_ROOT}/third_party/littlefs/lfs.c ${CANOKEY_ROOT}/third_party/littlefs/lfs_util.c)
      target_compile_definitions(storage-fixture-native PRIVATE CK_TEST_LITTLEFS WITH_ADMIN WITH_PASS WITH_OATH
        WITH_OPENPGP WITH_PIV WITH_CTAP WITH_NDEF LFS_NO_MALLOC LFS_NO_DEBUG LFS_NO_WARN LFS_NO_ERROR)
      target_include_directories(storage-fixture-native PRIVATE ${CANOKEY_PLATFORM_STORAGE_STUBS}
        ${CANOKEY_ROOT}/third_party/littlefs ${CANOKEY_ROOT}/crates/ports/include
        ${CANOKEY_ROOT}/native/support/include ${CANOKEY_ROOT}/crates/native-crypto/include)
      target_compile_options(storage-fixture-native PRIVATE -Wall -Wextra -UNDEBUG)
      if(CANOKEY_APDU_REPLAY AND CANOKEY_HOST_SANITIZERS)
        # add_rust_card links the same sanitizer runtimes into this native host.
        target_compile_options(storage-fixture-native PRIVATE -fsanitize=address,undefined -fno-omit-frame-pointer)
      endif()
      target_link_libraries(storage-fixture-native PRIVATE OpenSSL::Crypto host-key-services)
      if(CANOKEY_PLATFORM_STORAGE_MANIFEST)
        add_dependencies(storage-fixture-native platform-storage-bridge)
      endif()
      add_rust_card(storage-applet-host FALSE storage-applet-host)
      add_test(NAME native-storage-response COMMAND "${Python3_EXECUTABLE}"
        "${CANOKEY_ROOT}/tests/support/native_storage_faults.py"
        --host $<TARGET_FILE:storage-applet-host-image>
        --output "${CMAKE_CURRENT_BINARY_DIR}/native-storage-response.json")
      set_tests_properties(native-storage-response PROPERTIES TIMEOUT 120)
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
  add_test(NAME rust-transports COMMAND "${Python3_EXECUTABLE}"
    "${CANOKEY_ROOT}/tests/test_rust_transports.py"
    --target-dir "${CMAKE_CURRENT_BINARY_DIR}/cargo-transports")
  set_tests_properties(rust-transports PROPERTIES TIMEOUT 600)
endif()


if(ENABLE_TESTS)
  add_subdirectory(native)
endif()
get_property(correctness_tests DIRECTORY PROPERTY TESTS)
if(correctness_tests)
  set_property(TEST ${correctness_tests} APPEND PROPERTY ENVIRONMENT "UBSAN_OPTIONS=halt_on_error=1")
endif()
