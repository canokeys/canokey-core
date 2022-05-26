cmake_minimum_required(VERSION 3.7)
include(FindPkgConfig)
project(canokey-core C)

option(ENABLE_TESTS "Perform unit tests after build" OFF)
option(ENABLE_FUZZING "Build for fuzzing" OFF)
option(ENABLE_DEBUG_OUTPUT "Print debug messages" ON)
option(VIRTCARD "Virt Card" OFF)

# To be override by MCU specific cmakelists
set(TINYUSB_MCU "OPT_MCU_NONE" CACHE STRING "TinyUSB MCU name")
set(TINYUSB_DCD_INCLUDES "" CACHE STRING "TinyUSB DCD include paths")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-omit-frame-pointer")

if (ENABLE_DEBUG_OUTPUT)
    add_definitions(-DDEBUG_OUTPUT)
endif (ENABLE_DEBUG_OUTPUT)
if (ENABLE_TESTS OR ENABLE_FUZZING)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage -fsanitize=address -fsanitize=undefined")
    if (NOT CMAKE_C_COMPILER_ID MATCHES "Clang")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-usage")
    endif ()
endif ()

add_subdirectory(canokey-crypto EXCLUDE_FROM_ALL)

if (DEFINED USBD_PRODUCT_STRING)
    add_definitions(-DUSBD_PRODUCT_STRING="${USBD_PRODUCT_STRING}")
endif ()

add_definitions(-DCFG_TUSB_MCU=${TINYUSB_MCU})

file(GLOB_RECURSE SRC src/*.c applets/*.c interfaces/*.c 
        tinyusb/src/*.c littlefs/lfs.c littlefs/lfs_util.c
        tinycbor/src/cborencoder.c tinycbor/src/cborparser.c)
add_library(canokey-core ${SRC})

if (ENABLE_TESTS)
    target_compile_definitions(canokey-core PUBLIC TEST)
endif (ENABLE_TESTS)
if (ENABLE_FUZZING)
    target_compile_definitions(canokey-core PUBLIC TEST FUZZ)
    if (ENABLE_TESTS)
        message(WARNING "ENABLE_FUZZING will cause some tests to FAIL")
    endif (ENABLE_TESTS)
    # set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize-coverage=bb -finstrument-functions")
endif (ENABLE_FUZZING)

target_include_directories(canokey-core SYSTEM
        PUBLIC
        include
        littlefs
        tinycbor/src
        interfaces/USB/device
        interfaces/USB/class/ctaphid
        interfaces/USB/class/ccid
        interfaces/USB/class/webusb
        tinyusb/src
        ${TINYUSB_DCD_INCLUDES})
target_link_libraries(canokey-core canokey-crypto)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")

if (VIRTCARD OR ENABLE_TESTS OR ENABLE_FUZZING)
    set(gitrev_in virt-card/git-rev.h.in)
    set(gitrev virt-card/git-rev.h)
    add_custom_target(gitrev
            ${CMAKE_COMMAND} -E remove -f ${CMAKE_CURRENT_SOURCE_DIR}/${gitrev}
            COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/${gitrev_in} ${CMAKE_CURRENT_SOURCE_DIR}/${gitrev}
            COMMAND git describe --always --tags --long --abbrev=8 --dirty >> ${CMAKE_CURRENT_SOURCE_DIR}/${gitrev}
            )
endif ()

if (ENABLE_TESTS)
    find_package(CMocka CONFIG REQUIRED)
    include(AddCMockaTest)
    include(AddMockedTest)
    add_subdirectory(test)
    enable_testing()

    add_executable(fido-hid-over-udp
            virt-card/usb-dummy.c
            virt-card/device-sim.c
            virt-card/fabrication.c
            virt-card/fido-hid-over-udp.c
            littlefs/bd/lfs_filebd.c)
    target_include_directories(fido-hid-over-udp SYSTEM PRIVATE virt-card littlefs)
    target_link_libraries(fido-hid-over-udp general canokey-core "-fsanitize=address")

    pkg_search_module(PCSCLITE libpcsclite)
    if (PCSCLITE_FOUND)
        add_library(u2f-virt-card SHARED
                virt-card/usb-dummy.c
                virt-card/device-sim.c
                virt-card/ifdhandler.c
                virt-card/fabrication.c
                littlefs/bd/lfs_filebd.c)
        target_include_directories(u2f-virt-card SYSTEM PRIVATE virt-card ${PCSCLITE_INCLUDE_DIRS} littlefs)
        target_link_libraries(u2f-virt-card ${PCSCLITE_LIBRARIES} canokey-core)
        add_dependencies(u2f-virt-card gitrev)
    endif ()
endif (ENABLE_TESTS)

if (ENABLE_FUZZING)
    add_executable(honggfuzz-fuzzer
            fuzzer/honggfuzz-fuzzer.c
            virt-card/usb-dummy.c
            virt-card/device-sim.c
            virt-card/fabrication.c
            littlefs/bd/lfs_filebd.c)
    target_include_directories(honggfuzz-fuzzer SYSTEM PRIVATE virt-card littlefs)
    target_link_libraries(honggfuzz-fuzzer canokey-core)
    add_dependencies(honggfuzz-fuzzer gitrev)

    add_executable(honggfuzz-debug
            fuzzer/honggfuzz-debug.c
            fuzzer/honggfuzz-fuzzer.c
            virt-card/usb-dummy.c
            virt-card/device-sim.c
            virt-card/fabrication.c
            littlefs/bd/lfs_filebd.c)
    target_include_directories(honggfuzz-debug SYSTEM PRIVATE virt-card littlefs)
    target_link_libraries(honggfuzz-debug canokey-core)
    add_dependencies(honggfuzz-debug gitrev)
endif (ENABLE_FUZZING)
