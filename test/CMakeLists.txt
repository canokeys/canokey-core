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
set_tests_properties(test_fs PROPERTIES
    ENVIRONMENT "UBSAN_OPTIONS=halt_on_error=1")
