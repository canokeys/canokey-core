add_mocked_test(apdu
        SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/bd/lfs_filebd.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../tinycbor/src/cborvalidation.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/device-sim.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/usb-dummy.c
        LINK_LIBRARIES canokey-core
)
add_dependencies(test_apdu generate_virt_card_git_rev)
add_dependencies(test_apdu generate_canokey_core_git_rev)
target_include_directories(test_apdu SYSTEM BEFORE PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../tinycbor/src)
target_include_directories(test_apdu BEFORE PRIVATE ${CMAKE_SOURCE_DIR}/applets/ctap)

add_mocked_test(piv
        SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/bd/lfs_filebd.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/device-sim.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/usb-dummy.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../canokey-crypto/test/bignum.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../canokey-crypto/test/ecdsa-generic.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../canokey-crypto/test/nist256p1.c
        LINK_LIBRARIES canokey-core
)
add_dependencies(test_piv generate_virt_card_git_rev)
target_include_directories(test_piv PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../canokey-crypto/test)

# Thin LittleFS helpers have no applet, protocol, crypto or device-simulator dependency.
add_mocked_test(fs
        SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../src/fs.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/lfs.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/lfs_util.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/bd/lfs_filebd.c
)
target_include_directories(test_fs PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../include)
target_compile_definitions(test_fs PRIVATE TEST TESTMODE_INS_HOOKS)

# Sanitizer diagnostics are correctness failures, not passing-test log output.
set_tests_properties(test_apdu test_piv test_fs PROPERTIES
    ENVIRONMENT "UBSAN_OPTIONS=halt_on_error=1")
