cmake_minimum_required(VERSION 3.7)
include(FindPkgConfig)
project(canokey-core C)

option(ENABLE_TESTS "Perform unit tests after build" OFF)
option(ENABLE_FUZZING "Build for fuzzing" OFF)
option(ENABLE_DEBUG_OUTPUT "Print debug messages" ON)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-omit-frame-pointer")

if (ENABLE_DEBUG_OUTPUT)
    add_definitions(-DDEBUG_OUTPUT)
endif (ENABLE_DEBUG_OUTPUT)
if (ENABLE_TESTS)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-usage --coverage")
endif (ENABLE_TESTS)
if (ENABLE_FUZZING)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address")
endif (ENABLE_FUZZING)

add_subdirectory(canokey-crypto)


file(GLOB_RECURSE SRC src/*.c applets/*.c interfaces/*.c
        littlefs/lfs.c littlefs/lfs_util.c
        tinycbor/src/cborencoder.c tinycbor/src/cborparser.c)
add_library(canokey-core ${SRC})

if (ENABLE_TESTS)
    target_compile_definitions(canokey-core PUBLIC -DTEST)
endif (ENABLE_TESTS)
if (ENABLE_FUZZING)
    target_compile_definitions(canokey-core PUBLIC -DTEST -DFUZZ)
endif (ENABLE_FUZZING)

target_include_directories(canokey-core SYSTEM
        PUBLIC
        include
        littlefs
        tinycbor/src
        interfaces/USB/device
        interfaces/USB/core/inc
        interfaces/USB/class/ccid
        interfaces/USB/class/ctaphid
        interfaces/USB/class/webusb)
target_link_libraries(canokey-core canokey-crypto)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")

if (ENABLE_TESTS)
    find_package(CMocka CONFIG REQUIRED)
    include(AddCMockaTest)
    include(AddMockedTest)
    add_subdirectory(test)
    enable_testing()

    pkg_search_module(PCSCLITE libpcsclite)

    if (PCSCLITE_FOUND)
        add_library(u2f-virt-card SHARED
                virt-card/ifdhandler.c
                virt-card/fabrication.c
                littlefs/emubd/lfs_emubd.c)
        target_include_directories(u2f-virt-card SYSTEM PRIVATE virt-card ${PCSCLITE_INCLUDE_DIRS} littlefs)
        target_link_libraries(u2f-virt-card ${PCSCLITE_LIBRARIES} canokey-core)
    endif ()
endif (ENABLE_TESTS)

if (ENABLE_FUZZING)
    add_executable(honggfuzz-fuzzer
            fuzzer/honggfuzz-fuzzer.c
            fuzzer/dummy.c
            virt-card/fabrication.c
            littlefs/emubd/lfs_emubd.c)
    target_include_directories(honggfuzz-fuzzer SYSTEM PRIVATE virt-card littlefs)
    target_link_libraries(honggfuzz-fuzzer canokey-core)
endif (ENABLE_FUZZING)
