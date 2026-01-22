include(GoogleTest)

macro(add_hbft_core_test TEST_NAME SOURCE)
    add_executable(${TEST_NAME} ${SOURCE})
    target_link_libraries(${TEST_NAME} PRIVATE Honey::Core GTest::gtest_main)
    gtest_discover_tests(${TEST_NAME})
endmacro()

add_hbft_core_test(rbc_test test_rbc.cc)
# add_hbft_core_test(ba_core_test test_ba_core.cc)
# add_hbft_core_test(ba_driver_test test_ba_driver.cc)
# add_hbft_core_test(coin_core_test test_coin_core.cc)
# add_hbft_core_test(coin_driver_test test_coin_driver.cc)
# add_hbft_core_test(acs_test test_acs.cc)
# add_hbft_core_test(honeybadger_test test_honeybadger.cc)

# add_executable(asio_rbc_test asio_rbc_test.cc)
# target_link_libraries(asio_rbc_test
#     PRIVATE
#         Honey::Core
#         asio::asio
# )

# target_compile_definitions(asio_rbc_test PRIVATE ASIO_STANDALONE)

# add_test(NAME asio_rbc_test COMMAND asio_rbc_test)
