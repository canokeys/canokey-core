cmake_minimum_required(VERSION 3.16)
include(FindPkgConfig)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/ReleaseVersions.cmake)
project(canokey-core C)

option(ENABLE_TESTS "Perform unit tests after build" OFF)
option(ENABLE_APDU_REPLAY "Build the correctness APDU replay tool" OFF)
option(ENABLE_DEBUG_OUTPUT "Print debug messages" ON)
option(ENABLE_BYPASS_USER_PRESENCE "Skip all user-presence tests (USE AT YOUR OWN RISK)" OFF)
option(CTAP_RESTRICT_ALGORITHMS "Restrict FIDO credential algorithms to ES256 and Ed25519" OFF)
option(VIRTCARD "Build the complete Rust virtual-card host" OFF)

# Host tools exercise the Rust product engine. Do not link the superseded
# C dispatcher into a host executable and mistake it for a product oracle.
if(ENABLE_TESTS OR ENABLE_APDU_REPLAY OR VIRTCARD)
    foreach(applet NDEF CTAP PASS OATH OPENPGP PIV)
        set(CANOKEY_APPLET_${applet} ON)
    endforeach()
    set(CANOKEY_APDU_REPLAY ${ENABLE_APDU_REPLAY})
    set(CANOKEY_VIRTUAL_CARD ON)
    include(CTest)
    if(ENABLE_TESTS)
        set(CMAKE_C_STANDARD 11)
        set(CMAKE_C_STANDARD_REQUIRED ON)
        set(CMAKE_POSITION_INDEPENDENT_CODE ON)
        add_compile_options(-Wall --coverage -fsanitize=address -fsanitize=undefined)
        add_compile_options($<$<CONFIG:Debug>:-fno-omit-frame-pointer>)
        add_link_options(--coverage -fsanitize=address -fsanitize=undefined)
        if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
            add_compile_options(-fstack-usage)
        endif()
        list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")
        find_package(CMocka CONFIG REQUIRED)
        include(AddCMockaTest)
        include(AddMockedTest)
        add_subdirectory(test)
    endif()
    add_subdirectory(rust)
    return()
endif()

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall)
add_compile_options($<$<CONFIG:Debug>:-fno-omit-frame-pointer>)

if(NOT DEFINED ENABLE_NFC)
    if(DEFINED HW_VARIANT AND HW_VARIANT STREQUAL "HW_NFCC")
        set(ENABLE_NFC 1)
    elseif(DEFINED HW_VARIANT)
        set(ENABLE_NFC 0)
    else()
        set(ENABLE_NFC 1)
    endif()
endif()
if(NOT DEFINED ENABLE_APPLET_NDEF)
    set(ENABLE_APPLET_NDEF ${ENABLE_NFC})
endif()
if(ENABLE_APPLET_NDEF AND NOT ENABLE_NFC)
    message(FATAL_ERROR "ENABLE_APPLET_NDEF requires ENABLE_NFC")
endif()
if(NOT DEFINED ENABLE_PASS)
    if(DEFINED HAS_TOUCH)
        set(ENABLE_PASS ${HAS_TOUCH})
    else()
        set(ENABLE_PASS 1)
    endif()
endif()
if(NOT DEFINED ENABLE_IFACE_KBDHID)
    if(DEFINED HAS_TOUCH)
        set(ENABLE_IFACE_KBDHID ${HAS_TOUCH})
    else()
        set(ENABLE_IFACE_KBDHID 1)
    endif()
endif()
if(NOT DEFINED ENABLE_IFACE_CTAPHID)
    set(ENABLE_IFACE_CTAPHID 1)
endif()
if(NOT DEFINED ENABLE_IFACE_WEBUSB)
    set(ENABLE_IFACE_WEBUSB 1)
endif()
if(NOT DEFINED ENABLE_IFACE_CCID)
    set(ENABLE_IFACE_CCID 1)
endif()
if(ENABLE_DUMB_DONGLE)
    message(DEPRECATION "ENABLE_DUMB_DONGLE is deprecated; use ENABLE_BYPASS_USER_PRESENCE instead")
    set(ENABLE_BYPASS_USER_PRESENCE ON)
endif()

if(ENABLE_TESTS)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    add_compile_options(--coverage -fsanitize=address -fsanitize=undefined)
    add_link_options(--coverage -fsanitize=address -fsanitize=undefined)
    if(NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        add_compile_options(-fstack-usage)
    endif()
endif()

add_subdirectory(canokey-crypto EXCLUDE_FROM_ALL)

# tinycbor: build sources directly instead of add_subdirectory.
# tinycbor 7.0's CMakeLists.txt declares project(... LANGUAGES C CXX), which
# triggers unnecessary CXX compiler detection for C-only platform toolchains.
# Building its C sources here avoids requiring a C++ compiler and runtime.
set(TINYCBOR_DIR ${CMAKE_CURRENT_SOURCE_DIR}/tinycbor)
# Generate the two headers that tinycbor 7.0's cbor.h expects
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/tinycbor/tinycbor-export.h
    "#ifndef CBOR_API\n#define CBOR_API\n#endif\n")
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/tinycbor/tinycbor-version.h
    "#define TINYCBOR_VERSION_MAJOR 7\n#define TINYCBOR_VERSION_MINOR 0\n#define TINYCBOR_VERSION_PATCH 0\n")

# Generate pre-encoded CBOR segments for ctap_get_info.
# Constants are parsed directly from headers to avoid duplicating limits here.
find_program(PYTHON_EXE NAMES python3 python REQUIRED)
add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/ctap_get_info_cbor.inc
    COMMAND ${PYTHON_EXE}
        ${CMAKE_CURRENT_SOURCE_DIR}/scripts/gen_ctap_get_info.py
        --headers
            ${CMAKE_CURRENT_SOURCE_DIR}/applets/ctap/ctap-internal.h
            ${CMAKE_CURRENT_SOURCE_DIR}/applets/ctap/cose-key.h
            ${CANOKEY_RELEASE_VERSION_HEADER}
        --restrict-algorithms $<BOOL:${CTAP_RESTRICT_ALGORITHMS}>
        --credential-id-size 70
        --output ${CMAKE_CURRENT_BINARY_DIR}/ctap_get_info_cbor.inc
    DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/scripts/gen_ctap_get_info.py
        ${CMAKE_CURRENT_SOURCE_DIR}/applets/ctap/ctap-internal.h
        ${CMAKE_CURRENT_SOURCE_DIR}/applets/ctap/cose-key.h
        ${CANOKEY_RELEASE_VERSION_HEADER}
    COMMENT "Generating ctap_get_info_cbor.inc"
)
add_custom_target(
    generate_ctap_get_info_cbor
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/ctap_get_info_cbor.inc
)

add_custom_target(
    generate_canokey_core_git_rev ALL
    COMMAND ${CMAKE_COMMAND}
        -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -DOUTPUT_FILE=${CMAKE_CURRENT_BINARY_DIR}/canokey-core-git-rev.h
        -P ${CMAKE_CURRENT_SOURCE_DIR}/scripts/gen_git_rev_header.cmake
    BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/canokey-core-git-rev.h
    COMMENT "Generating canokey-core-git-rev.h"
    VERBATIM
)

file(
    GLOB_RECURSE SRC
    src/*.c
    applets/*.c
    interfaces/*.c
    littlefs/lfs.c
    littlefs/lfs_util.c
    tinycbor/src/cborencoder.c
    tinycbor/src/cborparser.c
)

# Independent Rust profiles select their adapters in the platform build.
list(FILTER SRC EXCLUDE REGEX ".*/interfaces/rust-core/.*\\.c$")

if(NOT ENABLE_NFC)
    list(FILTER SRC EXCLUDE REGEX ".*/interfaces/NFC/.*\\.c$")
endif()

if(NOT ENABLE_APPLET_NDEF)
    list(FILTER SRC EXCLUDE REGEX ".*/applets/ndef/.*\\.c$")
endif()

if(NOT ENABLE_IFACE_CTAPHID)
    list(FILTER SRC EXCLUDE REGEX ".*/interfaces/USB/class/ctaphid/.*\\.c$")
endif()

if(NOT ENABLE_IFACE_WEBUSB)
    list(FILTER SRC EXCLUDE REGEX ".*/interfaces/USB/class/webusb/.*\\.c$")
endif()

if(NOT ENABLE_IFACE_CCID)
    list(FILTER SRC EXCLUDE REGEX ".*/interfaces/USB/class/ccid/.*\\.c$")
endif()

if(NOT ENABLE_IFACE_KBDHID)
    list(FILTER SRC EXCLUDE REGEX ".*/interfaces/USB/class/kbdhid/.*\\.c$")
endif()

add_library(canokey-core ${SRC})

set(canokey_core_public_defs
    CTAP_RESTRICT_ALGORITHMS=$<BOOL:${CTAP_RESTRICT_ALGORITHMS}>
    ENABLE_NFC=$<BOOL:${ENABLE_NFC}>
    ENABLE_APPLET_NDEF=$<BOOL:${ENABLE_APPLET_NDEF}>
    ENABLE_PASS=$<BOOL:${ENABLE_PASS}>
    ENABLE_IFACE_CTAPHID=$<BOOL:${ENABLE_IFACE_CTAPHID}>
    ENABLE_IFACE_WEBUSB=$<BOOL:${ENABLE_IFACE_WEBUSB}>
    ENABLE_IFACE_CCID=$<BOOL:${ENABLE_IFACE_CCID}>
    ENABLE_IFACE_KBDHID=$<BOOL:${ENABLE_IFACE_KBDHID}>
)

set(canokey_core_private_defs
    CBOR_NO_FLOATING_POINT
    CBOR_STATIC_DEFINE
)

if(ENABLE_DEBUG_OUTPUT)
    list(APPEND canokey_core_private_defs DEBUG_OUTPUT)
endif()
if(ENABLE_BYPASS_USER_PRESENCE)
    list(APPEND canokey_core_private_defs BYPASS_USER_PRESENCE)
endif()
if(DEFINED PRODUCT_NAME)
    list(APPEND canokey_core_private_defs USBD_PRODUCT_STRING="${PRODUCT_NAME}")
endif()

if(ENABLE_TESTS)
    list(APPEND canokey_core_public_defs TEST TESTMODE_INS_HOOKS)
endif(ENABLE_TESTS)

target_compile_definitions(
    canokey-core
    PUBLIC ${canokey_core_public_defs}
    PRIVATE ${canokey_core_private_defs}
)

target_include_directories(
    canokey-core
    SYSTEM
    PUBLIC
        include
        littlefs
        tinycbor/src
        ${CMAKE_CURRENT_BINARY_DIR}/tinycbor
        ${CMAKE_CURRENT_BINARY_DIR}
        interfaces/USB/device
        interfaces/USB/core/inc
        interfaces/USB/class/ccid
        interfaces/USB/class/ctaphid
        interfaces/USB/class/kbdhid
        interfaces/USB/class/webusb
)
target_link_libraries(canokey-core canokey-crypto)
add_dependencies(canokey-core generate_ctap_get_info_cbor generate_canokey_core_git_rev)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")
