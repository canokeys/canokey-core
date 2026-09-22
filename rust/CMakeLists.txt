# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.20)
project(canokey_rust_core_host C)
option(CANOKEY_APPLET_PASS "Add the Rust PASS applet" OFF)
find_program(CARGO cargo REQUIRED)
set(FEATURES c-interface,host-runtime)
if(CANOKEY_APPLET_PASS)
  string(APPEND FEATURES ,pass)
endif()
set(ARCHIVE "${CMAKE_CURRENT_BINARY_DIR}/cargo/release/libcanokey_rust_core.a")
# This standalone build never includes the legacy core CMake/source glob.
add_custom_target(rust-core-build ALL
  COMMAND ${CARGO} +nightly-2026-09-04 rustc
    --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/core/Cargo.toml
    --target-dir ${CMAKE_CURRENT_BINARY_DIR}/cargo
    --release --features ${FEATURES} --crate-type staticlib
  BYPRODUCTS ${ARCHIVE} VERBATIM)
add_library(canokey-rust-core STATIC IMPORTED GLOBAL)
set_target_properties(canokey-rust-core PROPERTIES IMPORTED_LOCATION "${ARCHIVE}"
  INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/../interfaces/rust-core")
add_dependencies(canokey-rust-core rust-core-build)
include(CTest)
if(BUILD_TESTING)
  add_executable(core-normal core/tests/normal.c)
  target_compile_options(core-normal PRIVATE -Wall -Wextra -UNDEBUG)
  target_link_libraries(core-normal PRIVATE canokey-rust-core)
  if(CANOKEY_APPLET_PASS)
    find_package(OpenSSL REQUIRED)
    target_compile_definitions(core-normal PRIVATE WITH_PASS)
    target_link_libraries(core-normal PRIVATE OpenSSL::Crypto)
  endif()
  add_test(NAME core-normal COMMAND core-normal)
endif()
