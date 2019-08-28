add_mocked_test(u2f
        SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/emubd/lfs_emubd.c
        LINK_LIBRARIES canokey-core)

add_mocked_test(openpgp
        SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/emubd/lfs_emubd.c
        LINK_LIBRARIES canokey-core)

add_mocked_test(piv
        SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/emubd/lfs_emubd.c
        LINK_LIBRARIES canokey-core)

add_mocked_test(oath
        SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/emubd/lfs_emubd.c
        LINK_LIBRARIES canokey-core)
