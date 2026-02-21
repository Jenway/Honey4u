include(doctest)

function(add_hbft_service_test TEST_NAME SOURCE_FILE)
    add_executable(${TEST_NAME} ${SOURCE_FILE})

    target_link_libraries(${TEST_NAME}
        PRIVATE
            Honey::Protocol
            Honey::Service
            Honey::Crypto
            Honey::Core
            STDEXEC::stdexec
            doctest::doctest
    )

    set_target_properties(${TEST_NAME} PROPERTIES CXX_SCAN_FOR_MODULES OFF)
    add_test(NAME ${TEST_NAME} COMMAND ${TEST_NAME})

    if(DEFINED TEST_ENVIRONMENT)
        set_tests_properties(${TEST_NAME} PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")
    endif()
endfunction()

set(SERVICE_TESTS
    common_coin_test
    rbc_test
    ba_test
    # honeybadger_service_test
)

foreach(test_name ${SERVICE_TESTS})
    string(REPLACE "_test" "" test_source "${test_name}")
    add_hbft_service_test(${test_name} "test_${test_source}.cc")
endforeach()
