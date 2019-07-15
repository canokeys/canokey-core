add_mocked_test(u2f
        SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../src/core.c
        SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/../src/util.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../u2f/u2f.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/lfs.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/lfs_util.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/emubd/lfs_emubd.c
        LINK_LIBRARIES canokey-crypto)