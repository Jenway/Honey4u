enable_testing()

include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
)
FetchContent_MakeAvailable(googletest)

macro(add_hbft_test TEST_NAME SOURCE_FILE)
    add_executable(${TEST_NAME} ${SOURCE_FILE})
    target_link_libraries(${TEST_NAME}
        PRIVATE
            honey_crypto
            GTest::gtest
            GTest::gtest_main
    )
endmacro()

add_hbft_test(ecdsa_test test_ecdsa.cc)
add_hbft_test(tbls_test test_tbls.cc)
add_hbft_test(tpke_test test_tpke.cc)
add_hbft_test(merkle_tree_test test_merkle_tree.cc)
add_hbft_test(erasure_code_test test_erasure_code.cc)

include(GoogleTest)

if(TARGET ecdsa_test)
    gtest_discover_tests(ecdsa_test)
endif()
if(TARGET tbls_test)
    gtest_discover_tests(tbls_test)
endif()
if(TARGET tpke_test)
    gtest_discover_tests(tpke_test)
endif()
if(TARGET merkle_tree_test)
    gtest_discover_tests(merkle_tree_test)
endif()
if(TARGET erasure_code_test)
    gtest_discover_tests(erasure_code_test)
endif()