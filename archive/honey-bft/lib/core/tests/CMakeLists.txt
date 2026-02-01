include(GoogleTest)

macro(add_hbft_core_test TEST_NAME SOURCE)
    add_executable(${TEST_NAME} ${SOURCE})
    target_link_libraries(${TEST_NAME} PRIVATE Honey::Core GTest::gtest_main)
    gtest_discover_tests(${TEST_NAME})
endmacro()

add_hbft_core_test(rbc_test test_rbc.cc)
add_hbft_core_test(coin_core_test test_coin_core.cc)
add_hbft_core_test(ba_core_test test_ba_core.cc)
add_hbft_core_test(acs_core_test test_acs_core.cc)
add_hbft_core_test(hb_core_test test_hb_core.cc)
