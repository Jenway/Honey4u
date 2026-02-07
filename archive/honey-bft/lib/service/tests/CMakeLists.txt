include(GoogleTest)

function(add_hbft_service_test TEST_NAME SOURCE_FILE)
    add_executable(${TEST_NAME} ${SOURCE_FILE})

    target_link_libraries(${TEST_NAME}
        PRIVATE
            Honey::Service
            Honey::Crypto
            Honey::Core
            STDEXEC::stdexec
            GTest::gtest_main
    )

    set_target_properties(${TEST_NAME} PROPERTIES CXX_SCAN_FOR_MODULES OFF)
    gtest_discover_tests(${TEST_NAME})
endfunction()

set(SERVICE_TESTS
    crypto_service_test
    common_coin_test
    acs_test
    rbc_test
    ba_test
    # honeybadger_service_test
)

foreach(test_name ${SERVICE_TESTS})
    string(REPLACE "_test" "" test_source "${test_name}")
    add_hbft_service_test(${test_name} "test_${test_source}.cc")
endforeach()
