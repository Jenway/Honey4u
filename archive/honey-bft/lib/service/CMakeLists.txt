add_library(honey_service STATIC)
add_library(Honey::Service ALIAS honey_service)

file(GLOB_RECURSE HONEY_SERVICE_HEADERS
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    "include/*.h" "include/*.hpp" "include/**/*.h" "include/**/*.hpp"
)

target_compile_features(honey_service PUBLIC cxx_std_23)
set_target_properties(honey_service PROPERTIES CXX_SCAN_FOR_MODULES OFF)

target_sources(honey_service
    PUBLIC
        FILE_SET HEADERS
        BASE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include"
        FILES ${HONEY_SERVICE_HEADERS}
)

target_link_libraries(honey_service
    PUBLIC
        STDEXEC::stdexec
        asio::asio
        spdlog::spdlog
        Honey::Crypto
        Honey::Core
    PRIVATE
)

# nlohmann/json is header-only
target_include_directories(honey_service PUBLIC ${nlohmann_json_SOURCE_DIR}/include)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
