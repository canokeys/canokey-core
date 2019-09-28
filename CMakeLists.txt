cmake_minimum_required(VERSION 3.7)
include(FindPkgConfig)
project(canokey-core C)

option(ENABLE_TESTS "Perform unit tests after build" OFF)
if (ENABLE_TESTS)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif (ENABLE_TESTS)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -Wall -fstack-usage -fno-omit-frame-pointer --coverage")

if (ENABLE_TESTS)
    add_definitions(-DTEST -DNFC)
endif (ENABLE_TESTS)
add_subdirectory(canokey-crypto)

file(GLOB SRC src/*.c littlefs/*.c applets/ctap/*.c applets/openpgp/*.c applets/piv/*.c applets/oath/*.c applets/admin/*.c tinycbor/src/cborencoder.c tinycbor/src/cborparser.c)
add_library(canokey-core ${SRC})
target_include_directories(canokey-core SYSTEM PUBLIC include littlefs tinycbor/src)
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
                virt-card/apdu-adapter.c
                virt-card/fabrication.c
                littlefs/emubd/lfs_emubd.c)
        target_include_directories(u2f-virt-card SYSTEM PRIVATE virt-card ${PCSCLITE_INCLUDE_DIRS} littlefs)
        target_link_libraries(u2f-virt-card ${PCSCLITE_LIBRARIES} canokey-core)
    endif ()

    add_executable(fido-hid-over-udp
            virt-card/apdu-adapter.c
            virt-card/fabrication.c
            virt-card/ctap-hid.c
            virt-card/udp-server.c
            littlefs/emubd/lfs_emubd.c)
    target_include_directories(fido-hid-over-udp SYSTEM PRIVATE virt-card littlefs)
    target_link_libraries(fido-hid-over-udp general canokey-core asan)
    # target_link_libraries(fido-hid-over-udp debug gcov) # --coverage implies -lcov
    target_compile_options(fido-hid-over-udp PRIVATE "-fsanitize=address")
endif (ENABLE_TESTS)
