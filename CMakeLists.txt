cmake_minimum_required(VERSION 3.7)
project(canokey-core C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -g")

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
endif (ENABLE_TESTS)
