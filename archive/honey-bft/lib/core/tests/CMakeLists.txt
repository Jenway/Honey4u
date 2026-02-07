include(GoogleTest)

function(add_hbft_core_test TEST_NAME SOURCE_FILE)
    add_executable(${TEST_NAME} ${SOURCE_FILE})

    target_link_libraries(${TEST_NAME}
        PRIVATE
            Honey::Core
            GTest::gtest_main
    )

    gtest_discover_tests(${TEST_NAME})
endfunction()

set(CORE_TESTS
    rbc_core_test
    coin_core_test
    ba_core_test
    acs_core_test
    hb_core_test
)

foreach(test_name ${CORE_TESTS})
    string(REPLACE "_test" "" test_source "${test_name}")
    add_hbft_core_test(${test_name} "test_${test_source}.cc")
endforeach()
