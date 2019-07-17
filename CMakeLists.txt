cmake_minimum_required(VERSION 3.7)
include(FindPkgConfig)
project(canokey-core C)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -g")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fno-omit-frame-pointer -fsanitize=address")
set(CMAKE_SHARED_LINKER_FLAGS_DEBUG "${CMAKE_SHARED_LINKER_FLAGS_DEBUG} -lasan")

option(ENABLE_TESTS "Perform unit tests after build" OFF)
if (ENABLE_TESTS)
    add_definitions(-DTEST)
endif (ENABLE_TESTS)
add_subdirectory(canokey-crypto)

include_directories(include littlefs)
file(GLOB SRC src/*.c littlefs/*.c u2f/*.c)
add_library(canokey-core ${SRC})
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
        add_definitions(-DNFC)
        add_library(u2f-virt-card SHARED 
            virt-card/ifdhandler.c
            virt-card/apdu-adapter.c
            virt-card/fabrication.c
            littlefs/emubd/lfs_emubd.c)
        target_include_directories(u2f-virt-card SYSTEM PRIVATE u2f virt-card ${PCSCLITE_INCLUDE_DIRS})
        target_link_libraries(u2f-virt-card ${PCSCLITE_LIBRARIES} canokey-core)
    endif ()
endif (ENABLE_TESTS)
