# SPDX-License-Identifier: Apache-2.0
find_program(CARGO cargo REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
set(HOST_ARCHIVE "${CMAKE_CURRENT_BINARY_DIR}/cargo/release/libcanokey_rust_host.a")
add_custom_target(rust-host-build ALL
  COMMAND "${CMAKE_COMMAND}" -E env "CANOKEY_OATH_VERSION=${CANOKEY_OATH_VERSION}" "CANOKEY_PIV_VERSION=${CANOKEY_PIV_VERSION}"
    ${CARGO} +nightly-2026-09-04 build
    --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml
    --target-dir ${CMAKE_CURRENT_BINARY_DIR}/cargo --release
  BYPRODUCTS "${HOST_ARCHIVE}" VERBATIM)
add_library(canokey-rust-host STATIC IMPORTED GLOBAL)
set_target_properties(canokey-rust-host PROPERTIES IMPORTED_LOCATION "${HOST_ARCHIVE}")
add_dependencies(canokey-rust-host rust-host-build)
# Same native crypto facade as firmware; no C applet, dispatcher or USB stack.
add_library(virtual-key-services STATIC
  ../../interfaces/rust-core/key_crypto.c
  ../../interfaces/rust-core/digest_crypto.c
  ../../interfaces/rust-core/piv_crypto.c)
target_compile_definitions(virtual-key-services PRIVATE RUST_CORE_OPENPGP RUST_CORE_PIV RUST_CORE_CTAP)
target_link_libraries(virtual-key-services PUBLIC canokey-crypto)
add_executable(fido-hid-over-udp main.c crypto.c)
target_include_directories(fido-hid-over-udp PRIVATE ../../interfaces/rust-core)
target_compile_options(fido-hid-over-udp PRIVATE -Wall -Wextra -Werror -UNDEBUG)
target_link_libraries(fido-hid-over-udp PRIVATE canokey-rust-host virtual-key-services OpenSSL::Crypto Threads::Threads ${CMAKE_DL_LIBS} m)
set_target_properties(fido-hid-over-udp PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
find_path(PCSC_INCLUDE_DIR ifdhandler.h PATH_SUFFIXES PCSC REQUIRED)
add_library(u2f-virt-card SHARED pcsc.c crypto.c)
set_target_properties(u2f-virt-card PROPERTIES LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}")
target_include_directories(u2f-virt-card PRIVATE "${PCSC_INCLUDE_DIR}" ../../interfaces/rust-core)
target_compile_options(u2f-virt-card PRIVATE -Wall -Wextra -Werror -UNDEBUG)
target_link_libraries(u2f-virt-card PRIVATE canokey-rust-host virtual-key-services OpenSSL::Crypto Threads::Threads ${CMAKE_DL_LIBS} m)
if(BUILD_TESTING OR ENABLE_TESTS)
  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  add_test(NAME virtual-hid-udp COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/../core/tests/udp_normal.py" $<TARGET_FILE:fido-hid-over-udp>)
  # Fixed compatibility ports and presence-counter path are shared host resources.
  set_tests_properties(virtual-hid-udp PROPERTIES TIMEOUT 60 RESOURCE_LOCK virtual-card-udp)
  add_test(NAME virtual-pcsc COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/../core/tests/pcsc_normal.py" $<TARGET_FILE:u2f-virt-card>)
  set_tests_properties(virtual-pcsc PROPERTIES TIMEOUT 60 RESOURCE_LOCK virtual-card-udp)
  add_test(NAME virtual-oath-regressions COMMAND "${Python3_EXECUTABLE}"
    "${CMAKE_CURRENT_SOURCE_DIR}/../core/tests/oath_regressions.py" $<TARGET_FILE:u2f-virt-card>)
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
  endif()
  add_test(NAME virtual-storage COMMAND ${CARGO} +nightly-2026-09-04 test
    --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/Cargo.toml
    --target-dir ${CMAKE_CURRENT_BINARY_DIR}/cargo-tests --lib)
  set_tests_properties(virtual-storage PROPERTIES TIMEOUT 120)
endif()

if(BUILD_TESTING)
  get_property(host_correctness_tests DIRECTORY PROPERTY TESTS)
  set_property(TEST ${host_correctness_tests} APPEND PROPERTY ENVIRONMENT "UBSAN_OPTIONS=halt_on_error=1")
endif()
