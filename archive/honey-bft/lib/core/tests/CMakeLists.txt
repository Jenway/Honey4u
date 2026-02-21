include(doctest)

add_executable(honey_core_tests
    test_main.cc
    test_rbc_core.cc
    test_coin_core.cc
    test_ba_core.cc
)

target_link_libraries(honey_core_tests
    PRIVATE
        Honey::Core
        doctest::doctest
)

add_test(NAME honey_core_tests COMMAND honey_core_tests)

if(DEFINED TEST_ENVIRONMENT)
    set_tests_properties(honey_core_tests PROPERTIES ENVIRONMENT "${TEST_ENVIRONMENT}")
endif()
