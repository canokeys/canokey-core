add_mocked_test(openpgp
        SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/emubd/lfs_emubd.c ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/dummy.c
        LINK_LIBRARIES canokey-core)

add_mocked_test(oath
        SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/emubd/lfs_emubd.c ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/dummy.c
        LINK_LIBRARIES canokey-core)

add_mocked_test(apdu
        SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/dummy.c
        LINK_LIBRARIES canokey-core)
