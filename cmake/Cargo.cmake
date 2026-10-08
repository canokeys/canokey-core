# SPDX-License-Identifier: Apache-2.0
find_program(CARGO cargo REQUIRED)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CANOKEY_ROOT}/rust-toolchain.toml")
file(STRINGS "${CANOKEY_ROOT}/rust-toolchain.toml" toolchain_channel REGEX "^channel[ \t]*=")
if(NOT toolchain_channel MATCHES "^channel[ \t]*=[ \t]*\"([^\"]+)\"$")
  message(FATAL_ERROR "rust-toolchain.toml must define one quoted channel")
endif()
set(CANOKEY_RUST_TOOLCHAIN "${CMAKE_MATCH_1}")
function(add_rust_host_archive target build_target directory features)
  # Optional 5th argument: extra RUSTFLAGS (e.g. sanitizer coverage for fuzzing).
  set(rustflags "${ARGV4}")
  set(env_vars "CANOKEY_OATH_VERSION=${CANOKEY_OATH_VERSION}" "CANOKEY_PIV_VERSION=${CANOKEY_PIV_VERSION}")
  if(rustflags)
    list(APPEND env_vars "RUSTFLAGS=${rustflags}")
  endif()
  set(archive "${CMAKE_CURRENT_BINARY_DIR}/${directory}/host-test/libcanokey_rust_ffi.a")
  add_custom_target(${build_target} ALL
  COMMAND "${CMAKE_COMMAND}" -E env ${env_vars}
    ${CARGO} +${CANOKEY_RUST_TOOLCHAIN} rustc
    --manifest-path ${CANOKEY_ROOT}/crates/ffi/Cargo.toml
    --target-dir ${CMAKE_CURRENT_BINARY_DIR}/${directory}
    --profile host-test --features ${features} --crate-type staticlib
  BYPRODUCTS ${archive}
  DEPENDS ${CANOKEY_ROOT}/crates/ffi/Cargo.toml
          ${CANOKEY_ROOT}/crates/core/Cargo.toml
          ${CANOKEY_ROOT}/crates/ports/Cargo.toml
          ${CANOKEY_ROOT}/crates/native-crypto/Cargo.toml
          ${CANOKEY_ROOT}/crates/protocol/Cargo.toml
  VERBATIM)
  add_library(${target} STATIC IMPORTED GLOBAL)
  set_target_properties(${target} PROPERTIES IMPORTED_LOCATION "${archive}"
  INTERFACE_INCLUDE_DIRECTORIES "${CANOKEY_ROOT}/native/include")
  add_dependencies(${target} ${build_target})
endfunction()

function(add_rust_card target restricted)
  set(card_binary canokey-test-card)
  if(ARGV2)
    set(card_binary "${ARGV2}")
  endif()
  string(REPLACE "," ";" card_features "${FEATURES}")
  list(REMOVE_ITEM card_features host-runtime static-backend dynamic-backend)
  if(restricted)
    list(APPEND card_features ctap-restrict-algorithms)
  endif()
  if(card_binary STREQUAL "apdu-replay")
    list(APPEND card_features replay)
  elseif(card_binary STREQUAL "apdu-fuzzer")
    list(APPEND card_features fuzz)
  elseif(card_binary STREQUAL "core-behavior")
    list(APPEND card_features behavior)
  elseif(card_binary STREQUAL "runtime-composition")
    list(APPEND card_features composition)
  elseif(card_binary STREQUAL "hid-core-rust")
    list(APPEND card_features transport-hid)
  elseif(card_binary STREQUAL "usb-sessions-rust")
    list(APPEND card_features transport-usb)
  endif()
  list(JOIN card_features "," card_features)
  set(card_libraries "")
  set(card_dependencies "")
  if(TARGET card-crypto)
    set(card_libraries "$<TARGET_FILE:card-crypto>")
    list(APPEND card_dependencies card-crypto)
  endif()
  if(TARGET host-key-services)
    string(APPEND card_libraries "|$<TARGET_FILE:host-key-services>|$<TARGET_FILE:canokey-crypto>|$<TARGET_FILE:tfpsacrypto>")
    list(APPEND card_dependencies host-key-services canokey-crypto tfpsacrypto)
  endif()
  if(TARGET OpenSSL::Crypto)
    string(APPEND card_libraries "|$<TARGET_FILE:OpenSSL::Crypto>")
  endif()
  separate_arguments(card_options NATIVE_COMMAND "${CMAKE_EXE_LINKER_FLAGS}")
  get_directory_property(directory_options LINK_OPTIONS)
  list(APPEND card_options ${directory_options} -lm)
  if(CANOKEY_APDU_REPLAY AND CANOKEY_HOST_SANITIZERS)
    list(APPEND card_options -fsanitize=address,undefined)
  endif()
  if(ARGV3)
    list(APPEND card_options ${ARGV3})
  endif()
  if(card_binary STREQUAL "apdu-fuzzer")
    # Rust's -Zsanitizer supplies ASan/UBSan symbols; a second Clang ASan
    # runtime breaks macOS interceptor initialization.
    list(APPEND card_options -fno-sanitize-link-runtime)
  endif()
  list(JOIN card_options "|" card_options)
  set(card_image "${CMAKE_CURRENT_BINARY_DIR}/${target}")
  if(card_binary MATCHES "^apdu-(replay|fuzzer)$")
    set(card_image "${CMAKE_BINARY_DIR}/${target}")
  endif()
  set(card_environment "")
  if(ARGV4)
    list(APPEND card_environment "RUSTFLAGS=${ARGV4}")
  endif()
  if(card_binary STREQUAL "apdu-fuzzer")
    list(APPEND card_environment "CXX=${CMAKE_C_COMPILER}")
  endif()
  add_custom_target(${target}-build ALL
    COMMAND "${CMAKE_COMMAND}" -E env
      "CANOKEY_OATH_VERSION=${CANOKEY_OATH_VERSION}" "CANOKEY_PIV_VERSION=${CANOKEY_PIV_VERSION}"
      "CANOKEY_HOST_LINK_LIBRARIES=${card_libraries}" "CANOKEY_HOST_LINK_OPTIONS=${card_options}"
      ${card_environment}
      ${CARGO} +${CANOKEY_RUST_TOOLCHAIN} rustc --manifest-path ${CANOKEY_ROOT}/tests/card/Cargo.toml
      --target-dir ${CMAKE_CURRENT_BINARY_DIR}/cargo-${target} --profile host-test
      --features "${card_features}" --bin ${card_binary}
      -- -C "linker=${CMAKE_C_COMPILER}" -C default-linker-libraries=yes
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
      ${CMAKE_CURRENT_BINARY_DIR}/cargo-${target}/host-test/${card_binary} "${card_image}"
    BYPRODUCTS "${card_image}" DEPENDS ${card_dependencies} VERBATIM)
  if(card_binary MATCHES "^apdu-(replay|fuzzer)$")
    add_custom_target(${target} DEPENDS ${target}-build)
  endif()
  add_executable(${target}-image IMPORTED GLOBAL)
  set_target_properties(${target}-image PROPERTIES IMPORTED_LOCATION "${card_image}")
  add_dependencies(${target}-image ${target}-build)
endfunction()
