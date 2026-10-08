# SPDX-License-Identifier: Apache-2.0
# Host tools remain available when only regression execution is disabled.
find_package(OpenSSL REQUIRED)
if(CANOKEY_APDU_REPLAY)
  add_executable(apdu-replay ${CANOKEY_ROOT}/crates/host/native/replay.c ${CANOKEY_ROOT}/tests/support/services.c)
  target_compile_definitions(apdu-replay PRIVATE WITH_CTAP WITH_PASS WITH_OATH WITH_OPENPGP WITH_PIV WITH_NDEF)
  target_compile_options(apdu-replay PRIVATE -Wall -Wextra -Werror -UNDEBUG)
  option(CANOKEY_HOST_SANITIZERS "Enable ASan/UBSan in host replay adapters" ON)
  if(CANOKEY_HOST_SANITIZERS)
    target_compile_options(apdu-replay PRIVATE -fno-omit-frame-pointer -fsanitize=address,undefined)
    target_link_options(apdu-replay PRIVATE -fsanitize=address,undefined)
  endif()
  target_link_libraries(apdu-replay PRIVATE canokey-rust-core OpenSSL::Crypto host-key-services)
  set_target_properties(apdu-replay PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
  if(BUILD_TESTING)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(NAME apdu-replay COMMAND "${Python3_EXECUTABLE}"
    "${CANOKEY_ROOT}/tests/integration/replay_normal.py" $<TARGET_FILE:apdu-replay>)
    add_test(NAME fuzz-seed-baselines COMMAND "${Python3_EXECUTABLE}"
      "${CANOKEY_ROOT}/tests/support/fuzz_seeds.py" --validate-only --replay $<TARGET_FILE:apdu-replay>)
  endif()
endif()

if(CANOKEY_VIRTUAL_CARD)
  find_program(CARGO cargo REQUIRED)
  find_package(Threads REQUIRED)
  set(HOST_ARCHIVE "${CMAKE_CURRENT_BINARY_DIR}/cargo/host-test/libcanokey_rust_host.a")
  set(HOST_FEATURE_ARGS "")
  if(CTAP_RESTRICT_ALGORITHMS)
    list(APPEND HOST_FEATURE_ARGS --features ctap-restrict-algorithms)
  endif()
  add_custom_target(rust-host-build ALL
    COMMAND "${CMAKE_COMMAND}" -E env "CANOKEY_OATH_VERSION=${CANOKEY_OATH_VERSION}" "CANOKEY_PIV_VERSION=${CANOKEY_PIV_VERSION}"
      ${CARGO} +${CANOKEY_RUST_TOOLCHAIN} build
      --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml
      --target-dir ${CMAKE_CURRENT_BINARY_DIR}/cargo --profile host-test ${HOST_FEATURE_ARGS}
    BYPRODUCTS "${HOST_ARCHIVE}" VERBATIM)
  add_library(canokey-rust-host STATIC IMPORTED GLOBAL)
  set_target_properties(canokey-rust-host PROPERTIES IMPORTED_LOCATION "${HOST_ARCHIVE}")
  add_dependencies(canokey-rust-host rust-host-build)
  # Same native crypto facade as firmware; no C applet, dispatcher or USB stack.
  add_library(virtual-key-services STATIC
    ${CANOKEY_ROOT}/native/crypto/key_crypto.c
    ${CANOKEY_ROOT}/native/crypto/digest_crypto.c
    ${CANOKEY_ROOT}/native/crypto/piv_crypto.c)
  target_compile_definitions(virtual-key-services PRIVATE RUST_CORE_OPENPGP RUST_CORE_PIV RUST_CORE_CTAP)
  target_link_libraries(virtual-key-services PUBLIC canokey-crypto)
  target_include_directories(virtual-key-services PUBLIC "${CANOKEY_ROOT}/native/include")
  add_library(host-native-crypto STATIC native/crypto.c)
  target_link_libraries(host-native-crypto PRIVATE OpenSSL::Crypto virtual-key-services)
  target_include_directories(host-native-crypto PRIVATE ${CANOKEY_ROOT}/native/include)
  target_compile_options(host-native-crypto PRIVATE -Wall -Wextra -Werror -UNDEBUG)
  set(HOST_UDP_LIBRARIES "$<TARGET_FILE:host-native-crypto>|$<TARGET_FILE:virtual-key-services>|$<TARGET_FILE:OpenSSL::Crypto>|$<TARGET_FILE:canokey-crypto>|$<TARGET_FILE:tfpsacrypto>")
  separate_arguments(HOST_UDP_OPTIONS NATIVE_COMMAND "${CMAKE_EXE_LINKER_FLAGS}")
  get_directory_property(HOST_DIRECTORY_LINK_OPTIONS LINK_OPTIONS)
  list(APPEND HOST_UDP_OPTIONS ${HOST_DIRECTORY_LINK_OPTIONS})
  list(APPEND HOST_UDP_OPTIONS -lm)
  foreach(library IN LISTS CMAKE_DL_LIBS)
    list(APPEND HOST_UDP_OPTIONS "-l${library}")
  endforeach()
  list(JOIN HOST_UDP_OPTIONS "|" HOST_UDP_OPTIONS)
  set(HOST_UDP_IMAGE "${CMAKE_BINARY_DIR}/fido-hid-over-udp")
  add_custom_target(fido-hid-over-udp ALL
    COMMAND "${CMAKE_COMMAND}" -E env
      "CANOKEY_OATH_VERSION=${CANOKEY_OATH_VERSION}" "CANOKEY_PIV_VERSION=${CANOKEY_PIV_VERSION}"
      "CANOKEY_HOST_LINK_LIBRARIES=${HOST_UDP_LIBRARIES}" "CANOKEY_HOST_LINK_OPTIONS=${HOST_UDP_OPTIONS}"
      ${CARGO} +${CANOKEY_RUST_TOOLCHAIN} rustc
      --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml
      --target-dir ${CMAKE_CURRENT_BINARY_DIR}/cargo-udp --profile host-test
      --features udp-binary ${HOST_FEATURE_ARGS} --bin fido-hid-over-udp
      -- -C "linker=${CMAKE_C_COMPILER}" -C default-linker-libraries=yes
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
      "${CMAKE_CURRENT_BINARY_DIR}/cargo-udp/host-test/fido-hid-over-udp" "${HOST_UDP_IMAGE}"
    BYPRODUCTS "${HOST_UDP_IMAGE}"
    DEPENDS host-native-crypto virtual-key-services canokey-crypto tfpsacrypto VERBATIM)
  find_path(PCSC_INCLUDE_DIR ifdhandler.h PATH_SUFFIXES PCSC REQUIRED)
  add_library(u2f-virt-card SHARED native/pcsc.c native/crypto.c)
  set_target_properties(u2f-virt-card PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
  target_include_directories(u2f-virt-card PRIVATE "${PCSC_INCLUDE_DIR}" ${CANOKEY_ROOT}/native/include)
  target_compile_options(u2f-virt-card PRIVATE -Wall -Wextra -Werror -UNDEBUG)
  target_link_libraries(u2f-virt-card PRIVATE canokey-rust-host virtual-key-services OpenSSL::Crypto Threads::Threads ${CMAKE_DL_LIBS} m)
  if(BUILD_TESTING OR ENABLE_TESTS)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(NAME virtual-hid-udp COMMAND "${Python3_EXECUTABLE}"
      "${CANOKEY_ROOT}/tests/integration/udp_normal.py" "${HOST_UDP_IMAGE}")
    # Fixed compatibility ports and presence-counter path are shared host resources.
    set_tests_properties(virtual-hid-udp PROPERTIES TIMEOUT 60 RESOURCE_LOCK virtual-card-udp)
    set(PCSC_TEST_PYTHON "${Python3_EXECUTABLE}")
    if(APPLE AND ENABLE_TESTS)
      # Framework Python's launcher re-execs and loses DYLD_INSERT_LIBRARIES.
      # Start its real interpreter while retaining the selected virtual environment.
      execute_process(COMMAND "${Python3_EXECUTABLE}" -c
        "import pathlib,sys; p=pathlib.Path(sys.base_prefix)/'Resources/Python.app/Contents/MacOS/Python'; print(p if p.is_file() else sys.executable)"
        OUTPUT_VARIABLE PCSC_TEST_PYTHON OUTPUT_STRIP_TRAILING_WHITESPACE
        COMMAND_ERROR_IS_FATAL ANY)
    endif()
    add_test(NAME virtual-pcsc COMMAND "${PCSC_TEST_PYTHON}"
      "${CANOKEY_ROOT}/tests/integration/pcsc_normal.py" $<TARGET_FILE:u2f-virt-card>)
    set_tests_properties(virtual-pcsc PROPERTIES TIMEOUT 60 RESOURCE_LOCK virtual-card-udp)
    add_test(NAME virtual-oath-regressions COMMAND "${PCSC_TEST_PYTHON}"
      "${CANOKEY_ROOT}/tests/integration/oath_regressions.py" $<TARGET_FILE:u2f-virt-card>)
    set_tests_properties(virtual-oath-regressions PROPERTIES TIMEOUT 60 RESOURCE_LOCK virtual-card-udp)
    if(ENABLE_TESTS)
      # The legacy entry instruments its native libraries globally. ctypes loads
      # the IFD library into an unsanitized Python process: preload the matching
      # runtime instead of disabling ASan's library-order check.
      if(APPLE)
        set(asan_library libclang_rt.asan_osx_dynamic.dylib)
        set(asan_preload DYLD_INSERT_LIBRARIES)
      elseif(CMAKE_C_COMPILER_ID MATCHES "Clang")
        set(asan_library "libclang_rt.asan-${CMAKE_SYSTEM_PROCESSOR}.so")
        set(asan_preload LD_PRELOAD)
      else()
        set(asan_library libasan.so)
        set(asan_preload LD_PRELOAD)
      endif()
      execute_process(COMMAND "${CMAKE_C_COMPILER}" "-print-file-name=${asan_library}"
        OUTPUT_VARIABLE asan_runtime OUTPUT_STRIP_TRAILING_WHITESPACE
        COMMAND_ERROR_IS_FATAL ANY)
      if(NOT EXISTS "${asan_runtime}")
        message(FATAL_ERROR "Cannot locate the ASan runtime for Python IFD tests: ${asan_runtime}")
      endif()
      # Python/extension shutdown is not a native leak oracle. Dedicated native
      # crypto tests retain LeakSanitizer; bounds checks remain active here.
      set_tests_properties(virtual-pcsc virtual-oath-regressions PROPERTIES ENVIRONMENT
        "${asan_preload}=${asan_runtime};ASAN_OPTIONS=detect_leaks=0:abort_on_error=1")
      if(APPLE)
        set_property(TEST virtual-pcsc virtual-oath-regressions APPEND PROPERTY ENVIRONMENT
          "__PYVENV_LAUNCHER__=${Python3_EXECUTABLE}")
      endif()
    endif()
    add_test(NAME virtual-storage COMMAND ${CARGO} +${CANOKEY_RUST_TOOLCHAIN} test
      --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml
      --target-dir ${CMAKE_CURRENT_BINARY_DIR}/cargo-tests --lib)
    set_tests_properties(virtual-storage PROPERTIES TIMEOUT 120)
  endif()

  if(BUILD_TESTING)
    get_property(host_correctness_tests DIRECTORY PROPERTY TESTS)
    set_property(TEST ${host_correctness_tests} APPEND PROPERTY ENVIRONMENT "UBSAN_OPTIONS=halt_on_error=1")
  endif()

endif()

if(CANOKEY_FUZZING)
  find_package(Threads REQUIRED)
  # libFuzzer coverage instrumentation for the Rust side; the C side gets
  # -fsanitize=fuzzer-no-link from the top-level CANOKEY_FUZZING block.
  add_rust_host_archive(canokey-rust-core-fuzz rust-core-fuzz-build cargo-fuzz "${FEATURES}"
    "-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table -Cllvm-args=-sanitizer-coverage-trace-compares -Cdebug-assertions=on -Cforce-frame-pointers=yes -Zsanitizer=address")
  add_executable(apdu-fuzzer native/fuzz.c ${CANOKEY_ROOT}/tests/support/services.c)
  target_compile_definitions(apdu-fuzzer PRIVATE WITH_CTAP WITH_PASS WITH_OATH WITH_OPENPGP WITH_PIV WITH_NDEF)
  target_compile_options(apdu-fuzzer PRIVATE -Wall -Wextra -Werror -UNDEBUG)
  target_link_options(apdu-fuzzer PRIVATE -fsanitize=fuzzer)
  target_link_libraries(apdu-fuzzer PRIVATE canokey-rust-core-fuzz OpenSSL::Crypto host-key-services
    Threads::Threads ${CMAKE_DL_LIBS} m)
  set_target_properties(apdu-fuzzer PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
  if(BUILD_TESTING)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    add_test(NAME fuzz-smoke COMMAND "${Python3_EXECUTABLE}"
      "${CANOKEY_ROOT}/tests/support/fuzz_smoke.py" $<TARGET_FILE:apdu-fuzzer>
      "${CANOKEY_ROOT}/tests/fixtures/fuzz-seeds")
    set_tests_properties(fuzz-smoke PROPERTIES TIMEOUT 120)
  endif()
endif()
