# Thin LittleFS helpers have no applet, protocol, crypto or device-simulator dependency.
add_mocked_test(fs
        SOURCES
        ${CANOKEY_ROOT}/native/storage/fs.c
        ${CANOKEY_ROOT}/third_party/littlefs/lfs.c
        ${CANOKEY_ROOT}/third_party/littlefs/lfs_util.c
        ${CANOKEY_ROOT}/third_party/littlefs/bd/lfs_filebd.c
)
target_include_directories(test_fs PRIVATE ${CANOKEY_ROOT}/native/include)
target_compile_definitions(test_fs PRIVATE TEST TESTMODE_INS_HOOKS)

# Sanitizer diagnostics are correctness failures, not passing-test log output.
set_tests_properties(test_fs PROPERTIES
    ENVIRONMENT "UBSAN_OPTIONS=halt_on_error=1")
