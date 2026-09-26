add_mocked_test(openpgp
        SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/bd/lfs_filebd.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/device-sim.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/usb-dummy.c
        LINK_LIBRARIES canokey-core
)
add_dependencies(test_openpgp generate_virt_card_git_rev)

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

add_mocked_test(key
        SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/bd/lfs_filebd.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/device-sim.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/usb-dummy.c
        LINK_LIBRARIES canokey-core
)
add_dependencies(test_key generate_virt_card_git_rev)

# Sanitizer diagnostics are correctness failures, not passing-test log output.
set_tests_properties(test_openpgp test_apdu test_piv test_key PROPERTIES
    ENVIRONMENT "UBSAN_OPTIONS=halt_on_error=1")
