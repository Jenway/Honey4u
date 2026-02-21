add_executable(hbbft_node main.cpp)

target_link_libraries(hbbft_node
    PRIVATE
        Honey::Core
        Honey::Crypto
        Honey::Protocol
        Honey::Service
)

target_include_directories(hbbft_node PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")

add_executable(honeybadger_demo demo/main.cc)

target_link_libraries(honeybadger_demo
    PRIVATE
        Honey::Core
        Honey::Protocol
        Honey::Service
        Honey::Crypto
        spdlog::spdlog
)

target_include_directories(honeybadger_demo PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")

# network_test disabled due to clang-scan-deps Windows issue
# add_executable(network_test network_test.cc)
# target_link_libraries(network_test
#     PRIVATE
#         Honey::Service
#         spdlog::spdlog
#         STDEXEC::stdexec
# )
# target_include_directories(network_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")

install(TARGETS hbbft_node honeybadger_demo
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
