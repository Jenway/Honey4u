include(GoogleTest)

# Test helper function
function(add_hbft_test TEST_NAME SOURCE_FILE)
    add_executable(${TEST_NAME} ${SOURCE_FILE})

    target_link_libraries(${TEST_NAME}
        PRIVATE
            honey_crypto
            GTest::gtest
            GTest::gtest_main
    )

    target_include_directories(${TEST_NAME} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/../src"
    )

    gtest_discover_tests(${TEST_NAME})
endfunction()

# Define test cases
set(CRYPTO_TESTS
    ecdsa_test
    tbls_test
    tpke_test
    merkle_tree_test
    erasure_code_test
    serialization_test
)

foreach(test_name ${CRYPTO_TESTS})
    string(REPLACE "_test" "" test_source "${test_name}")
    add_hbft_test(${test_name} "test_${test_source}.cc")
endforeach()
