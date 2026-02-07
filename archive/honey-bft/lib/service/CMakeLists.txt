add_library(honey_service STATIC)
add_library(Honey::Service ALIAS honey_service)

file(GLOB_RECURSE HONEY_SERVICE_HEADERS
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    include/*.h include/*.hpp include/**/*.h include/**/*.hpp
)

target_sources(honey_service
    PRIVATE
        src/async_crypto_service.cc
        src/tcp_transport.cc
    PUBLIC
        FILE_SET HEADERS
        BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include
        FILES ${HONEY_SERVICE_HEADERS}
)

target_link_libraries(honey_service
    PRIVATE
    Honey::Crypto
    Honey::Core
    STDEXEC::stdexec
)

set_target_properties(honey_service PROPERTIES CXX_SCAN_FOR_MODULES OFF)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
