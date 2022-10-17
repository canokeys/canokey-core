add_mocked_test(openpgp
        SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/bd/lfs_filebd.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/device-sim.c
        LINK_LIBRARIES canokey-core)

add_mocked_test(oath
        SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/bd/lfs_filebd.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/device-sim.c
        LINK_LIBRARIES canokey-core)

add_mocked_test(apdu
        SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/bd/lfs_filebd.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/device-sim.c
        LINK_LIBRARIES canokey-core)

add_mocked_test(piv
        SOURCES
        ${CMAKE_CURRENT_SOURCE_DIR}/../littlefs/bd/lfs_filebd.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../virt-card/device-sim.c
        LINK_LIBRARIES canokey-core)