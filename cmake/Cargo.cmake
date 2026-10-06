# SPDX-License-Identifier: Apache-2.0
find_program(CARGO cargo REQUIRED)
function(add_rust_host_archive target build_target directory features)
  # Optional 5th argument: extra RUSTFLAGS (e.g. sanitizer coverage for fuzzing).
  set(rustflags "${ARGV4}")
  set(env_vars "CANOKEY_OATH_VERSION=${CANOKEY_OATH_VERSION}" "CANOKEY_PIV_VERSION=${CANOKEY_PIV_VERSION}")
  if(rustflags)
    list(APPEND env_vars "RUSTFLAGS=${rustflags}")
  endif()
  set(archive "${CMAKE_CURRENT_BINARY_DIR}/${directory}/release/libcanokey_rust_ffi.a")
  add_custom_target(${build_target} ALL
  COMMAND "${CMAKE_COMMAND}" -E env ${env_vars}
    ${CARGO} +nightly-2026-09-04 rustc
    --manifest-path ${CANOKEY_ROOT}/crates/ffi/Cargo.toml
    --target-dir ${CMAKE_CURRENT_BINARY_DIR}/${directory}
    --release --features ${features} --crate-type staticlib
  BYPRODUCTS ${archive}
  DEPENDS ${CANOKEY_ROOT}/crates/ffi/Cargo.toml
          ${CANOKEY_ROOT}/crates/core/Cargo.toml
          ${CANOKEY_ROOT}/crates/ports/Cargo.toml
          ${CANOKEY_ROOT}/crates/protocol/Cargo.toml
  VERBATIM)
  add_library(${target} STATIC IMPORTED GLOBAL)
  set_target_properties(${target} PROPERTIES IMPORTED_LOCATION "${archive}"
  INTERFACE_INCLUDE_DIRECTORIES "${CANOKEY_ROOT}/native/include")
  add_dependencies(${target} ${build_target})
endfunction()
