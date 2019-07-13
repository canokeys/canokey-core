cmake_minimum_required(VERSION 3.7)
project(canokey-core C)

set(CMAKE_C_STANDARD 11)

add_subdirectory(canokey-crypto)

add_executable(canokey-core main.c)
target_link_libraries(canokey-core canokey-crypto)
