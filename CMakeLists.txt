cmake_minimum_required(VERSION 3.7)
include(FindPkgConfig)
include(CMakeDependentOption)
project(canokey-core C)

option(USBIP "Virtual Canokey using USBIP" OFF)
option(QEMU "Virtual Canokey for QEMU" OFF)
option(FFS "Virtual Canokey using FunctionFS" OFF)

option(ENABLE_TESTS "Perform unit tests after build" OFF)
option(ENABLE_FUZZING "Build for fuzzing" OFF)
cmake_dependent_option(ENABLE_DEBUG_OUTPUT "Print debug messages" OFF "QEMU" ON)

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
if (QEMU)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif (QEMU)

add_subdirectory(canokey-crypto EXCLUDE_FROM_ALL)

if (DEFINED USBD_PRODUCT_STRING)
    add_definitions(-DUSBD_PRODUCT_STRING="${USBD_PRODUCT_STRING}")
endif ()

file(GLOB_RECURSE SRC src/*.c applets/*.c interfaces/*.c
        littlefs/lfs.c littlefs/lfs_util.c
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
        interfaces/USB/core/inc
        interfaces/USB/class/ccid
        interfaces/USB/class/ctaphid
        interfaces/USB/class/kbdhid
        interfaces/USB/class/webusb)
target_link_libraries(canokey-core canokey-crypto)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules")

if (USBIP OR QEMU OR FFS OR ENABLE_TESTS OR ENABLE_FUZZING)
    set(gitrev_in virt-card/git-rev.h.in)
    set(gitrev virt-card/git-rev.h)
    add_custom_target(gitrev
            ${CMAKE_COMMAND} -E remove -f ${CMAKE_CURRENT_SOURCE_DIR}/${gitrev}
            COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/${gitrev_in} ${CMAKE_CURRENT_SOURCE_DIR}/${gitrev}
            COMMAND git describe --always --tags --long --abbrev=8 --dirty >> ${CMAKE_CURRENT_SOURCE_DIR}/${gitrev}
            )
endif ()

if (QEMU)
    include(GNUInstallDirs)
    set(LIBCANOKEY_QEMU_SO_VERSION 0)
    set(LIBCANOKEY_QEMU_PREFIX ${CMAKE_INSTALL_PREFIX})
    set(LIBCANOKEY_QEMU_LIBDIR ${CMAKE_INSTALL_FULL_LIBDIR})
    set(LIBCANOKEY_QEMU_INCLUDEDIR ${CMAKE_INSTALL_FULL_INCLUDEDIR})

    add_library(canokey-qemu SHARED
            virt-card/qemu.c
            virt-card/device-sim.c
            virt-card/fabrication.c
            littlefs/bd/lfs_filebd.c)
    set_target_properties(canokey-qemu PROPERTIES PUBLIC_HEADER virt-card/canokey-qemu.h)
    set_target_properties(canokey-qemu PROPERTIES SOVERSION ${LIBCANOKEY_QEMU_SO_VERSION})
    target_include_directories(canokey-qemu SYSTEM PRIVATE littlefs)
    target_compile_definitions(canokey-qemu PRIVATE HW_VARIANT_NAME="CanoKey QEMU")
    target_compile_options(canokey-qemu PRIVATE)
    target_link_libraries(canokey-qemu general canokey-core)
    add_dependencies(canokey-qemu gitrev)
    install(TARGETS canokey-qemu LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
            PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

    configure_file(virt-card/canokey-qemu.pc.in canokey-qemu.pc @ONLY)
    install(FILES ${CMAKE_BINARY_DIR}/canokey-qemu.pc
            DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR}/pkgconfig)
endif (QEMU)

if (USBIP)
    add_executable(canokey-usbip
            virt-card/device-sim.c
            virt-card/usbip.c
            virt-card/fabrication.c
            littlefs/bd/lfs_filebd.c)
    target_include_directories(canokey-usbip SYSTEM PRIVATE littlefs)
    target_compile_definitions(canokey-usbip PRIVATE HW_VARIANT_NAME="CanoKey USB/IP")
    target_compile_options(canokey-usbip PRIVATE "-fsanitize=address")
    find_package(Threads)
    target_link_libraries(canokey-usbip general canokey-core "-fsanitize=address" Threads::Threads)
    add_dependencies(canokey-usbip gitrev)
endif (USBIP)

if (FFS)
    add_executable(canokey-ffs
            virt-card/device-sim.c
            virt-card/ffs.c
            virt-card/fabrication.c
            littlefs/bd/lfs_filebd.c)
    target_include_directories(canokey-ffs SYSTEM PRIVATE littlefs)
    target_compile_definitions(canokey-ffs PRIVATE HW_VARIANT_NAME="CanoKey FunctionFS")
    target_compile_options(canokey-ffs PRIVATE "-fsanitize=address")
    find_package (Threads)
    target_link_libraries(canokey-ffs general canokey-core "-fsanitize=address" Threads::Threads)
    add_dependencies(canokey-ffs gitrev)
endif (FFS)

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
