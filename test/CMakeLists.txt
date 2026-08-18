add_mocked_test(openpgp
        SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/bd/lfs_filebd.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/device-sim.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/usb-dummy.c
        LINK_LIBRARIES canokey-core
)

add_mocked_test(oath
        SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/bd/lfs_filebd.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/device-sim.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/usb-dummy.c
        LINK_LIBRARIES canokey-core
)

add_mocked_test(apdu
        SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/bd/lfs_filebd.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../tinycbor/src/cborvalidation.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/device-sim.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/usb-dummy.c
        LINK_LIBRARIES canokey-core
)
add_dependencies(test_apdu generate_canokey_core_git_rev)
target_include_directories(test_apdu SYSTEM BEFORE PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../tinycbor/src)

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
target_include_directories(test_piv PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../canokey-crypto/test)

add_mocked_test(key
        SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/bd/lfs_filebd.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/device-sim.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/usb-dummy.c
        LINK_LIBRARIES canokey-core
)

add_mocked_test(core_helpers
        SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/bd/lfs_filebd.c
        LINK_LIBRARIES canokey-core
)
