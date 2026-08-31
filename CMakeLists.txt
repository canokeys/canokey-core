cmake_minimum_required(VERSION 3.16)
include(FindPkgConfig)
project(canokey-core C)

option(ENABLE_TESTS "Perform unit tests after build" OFF)
option(ENABLE_FUZZING "Build the AFL++ harness with GNU GCC" OFF)
option(ENABLE_APDU_REPLAY "Build the differential-fuzz APDU replay tool (card semantics, without the FUZZ gates)" OFF)
option(ENABLE_DEBUG_OUTPUT "Print debug messages" ON)
option(ENABLE_BYPASS_USER_PRESENCE "Skip all user-presence tests (USE AT YOUR OWN RISK)" OFF)
option(VIRTCARD "Virt Card" OFF)

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

if(ENABLE_FUZZING)
    if(NOT CMAKE_C_COMPILER_ID STREQUAL "GNU")
        message(FATAL_ERROR "ENABLE_FUZZING requires GNU GCC (directly or through afl-gcc-fast)")
    endif()
    # Sanitizers are on by default. AFL++ Frida mode (macOS binary-only
    # fuzzing) cannot lift the ASan runtime; use -DCANOKEY_FUZZ_SANITIZERS=OFF
    # there and rely on Frida coverage plus real crashes.
    set(CANOKEY_FUZZ_SANITIZERS ON CACHE BOOL "Enable ASan/UBSan in fuzz builds")
    if(CANOKEY_FUZZ_SANITIZERS)
        add_compile_options(-fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined)
        add_link_options(-fsanitize=address -fsanitize=undefined)
    endif()
endif()

add_subdirectory(canokey-crypto EXCLUDE_FROM_ALL)

# tinycbor: build sources directly instead of add_subdirectory.
# tinycbor 7.0's CMakeLists.txt declares project(... LANGUAGES C CXX), which
# triggers CXX compiler detection. On ARM cross-compilation the CXX test
# program fails to link against the scatter file (L6236E: no RESET section).
# Avoid this by not using tinycbor's own CMake build system.
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
        --credential-id-size 70
        --output ${CMAKE_CURRENT_BINARY_DIR}/ctap_get_info_cbor.inc
    DEPENDS
        ${CMAKE_CURRENT_SOURCE_DIR}/scripts/gen_ctap_get_info.py
        ${CMAKE_CURRENT_SOURCE_DIR}/applets/ctap/ctap-internal.h
        ${CMAKE_CURRENT_SOURCE_DIR}/applets/ctap/cose-key.h
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
if(ENABLE_FUZZING)
    list(APPEND canokey_core_public_defs TEST FUZZ TESTMODE_INS_HOOKS)
    if(ENABLE_TESTS)
        message(WARNING "ENABLE_FUZZING will cause some tests to FAIL")
    endif(ENABLE_TESTS)
endif(ENABLE_FUZZING)
# The replay tool must reproduce on-device semantics, so it gets the TEST
# hooks (device-sim, LittleFS file backend) but NOT the FUZZ gates, which
# skip PIN/touch verification paths that real fuzz firmware keeps active, and
# NOT TESTMODE_INS_HOOKS (the INS 0xEE/0xEF test hooks do not exist on real
# firmware and would desynchronize the differential comparison).
if(ENABLE_APDU_REPLAY)
    list(APPEND canokey_core_public_defs TEST)
endif(ENABLE_APDU_REPLAY)

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

if(VIRTCARD OR ENABLE_TESTS OR ENABLE_FUZZING OR ENABLE_APDU_REPLAY)
    set(VIRT_CARD_GIT_REV_HEADER ${CMAKE_CURRENT_BINARY_DIR}/virt-card-git-rev.h)
    add_custom_target(
        generate_virt_card_git_rev
        COMMAND ${CMAKE_COMMAND}
            -DSOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
            -DOUTPUT_FILE=${VIRT_CARD_GIT_REV_HEADER}
            -P ${CMAKE_CURRENT_SOURCE_DIR}/scripts/gen_virt_card_git_rev_header.cmake
        BYPRODUCTS ${VIRT_CARD_GIT_REV_HEADER}
        COMMENT "Generating virt-card git revision"
        VERBATIM
    )

    function(add_virt_card_git_revision target)
        add_dependencies(${target} generate_virt_card_git_rev)
        target_include_directories(${target} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    endfunction()
endif()

if(ENABLE_TESTS)
    find_package(CMocka CONFIG REQUIRED)
    include(AddCMockaTest)
    include(AddMockedTest)
    add_subdirectory(test)
    enable_testing()

    add_executable(
        fido-hid-over-udp
        virt-card/usb-dummy.c
        virt-card/device-sim.c
        virt-card/fabrication.c
        virt-card/fido-hid-over-udp.c
        littlefs/bd/lfs_filebd.c
    )
    target_include_directories(
        fido-hid-over-udp
        SYSTEM
        PRIVATE virt-card littlefs
    )
    target_link_libraries(
        fido-hid-over-udp
        general
        canokey-core
        "-fsanitize=address"
    )
    add_virt_card_git_revision(fido-hid-over-udp)

    pkg_search_module(PCSCLITE libpcsclite)
    if(PCSCLITE_FOUND)
        add_library(
            u2f-virt-card
            SHARED
            virt-card/usb-dummy.c
            virt-card/device-sim.c
            virt-card/ifdhandler.c
            virt-card/fabrication.c
            littlefs/bd/lfs_filebd.c
        )
        target_include_directories(
            u2f-virt-card
            SYSTEM
            PRIVATE virt-card ${PCSCLITE_INCLUDE_DIRS} littlefs
        )
        target_link_libraries(u2f-virt-card ${PCSCLITE_LIBRARIES} canokey-core)
        add_virt_card_git_revision(u2f-virt-card)
    endif()
endif(ENABLE_TESTS)

if(ENABLE_FUZZING)
    add_executable(
        afl-fuzzer
        fuzzer/afl-fuzzer.c
        virt-card/usb-dummy.c
        virt-card/device-sim.c
        virt-card/fabrication.c
        littlefs/bd/lfs_filebd.c
    )
    target_include_directories(
        afl-fuzzer
        SYSTEM
        PRIVATE virt-card littlefs
    )
    target_link_libraries(afl-fuzzer canokey-core)
    add_virt_card_git_revision(afl-fuzzer)
endif(ENABLE_FUZZING)

if(ENABLE_APDU_REPLAY)
    set(CANOKEY_FUZZ_SANITIZERS ON CACHE BOOL "Enable ASan/UBSan in fuzz builds")
    if(CANOKEY_FUZZ_SANITIZERS)
        add_compile_options(-fno-omit-frame-pointer -fsanitize=address -fsanitize=undefined)
        add_link_options(-fsanitize=address -fsanitize=undefined)
    endif()
    # Host half of the differential APDU fuzzer: replays a line-based hex
    # APDU stream from stdin through the virtual card and prints RESP/ERROR
    # lines on stdout (see fuzzer/apdu-replay.c).
    add_executable(
        apdu-replay
        fuzzer/apdu-replay.c
        virt-card/usb-dummy.c
        virt-card/device-sim.c
        virt-card/fabrication.c
        littlefs/bd/lfs_filebd.c
    )
    target_include_directories(
        apdu-replay
        SYSTEM
        PRIVATE virt-card littlefs
    )
    target_link_libraries(apdu-replay canokey-core)
    add_virt_card_git_revision(apdu-replay)
endif(ENABLE_APDU_REPLAY)
