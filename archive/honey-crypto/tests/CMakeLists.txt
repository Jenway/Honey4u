include("${doctest_DIR}/doctest.cmake")

add_executable(honey_crypto_tests
    main.cc
)

target_link_libraries(honey_crypto_tests
    PRIVATE
        $<LINK_LIBRARY:WHOLE_ARCHIVE,Honey::Crypto>
        doctest::doctest
)
# add_test(NAME honey_crypto_tests COMMAND honey_crypto_tests)
doctest_discover_tests(honey_crypto_tests)
