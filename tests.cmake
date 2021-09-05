enable_testing()

set(ROOT_SRC_WITHOUT_MAIN ${ROOT_SRC})
list(REMOVE_ITEM ROOT_SRC_WITHOUT_MAIN "src/main.c")

function(read_tests directory)
    find_src(${directory} TEST_FILES)

    foreach(TEST_FILE ${TEST_FILES})
        get_filename_component(TEST_NAME ${TEST_FILE} NAME_WE)
        add_executable("${TEST_NAME}_test"
                       ${TEST_FILE}
                       ${ROOT_SRC_WITHOUT_MAIN}
                       ${ARCH_SRC}
                       ${SUBDIRECTORIES_SRC})

        add_test(NAME ${TEST_NAME} COMMAND "${TEST_NAME}_test")
    endforeach()
endfunction()

foreach(TEST ${TESTDIRS})
    read_tests(${TEST})
endforeach()
