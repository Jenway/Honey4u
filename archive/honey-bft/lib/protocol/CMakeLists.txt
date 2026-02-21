add_library(honey_protocol STATIC)
add_library(Honey::Protocol ALIAS honey_protocol)

file(GLOB_RECURSE HONEY_PROTOCOL_HEADERS
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    "include/*.h" "include/*.hpp" "include/**/*.h" "include/**/*.hpp"
)

target_compile_features(honey_protocol PUBLIC cxx_std_23)
set_target_properties(honey_protocol PROPERTIES CXX_SCAN_FOR_MODULES OFF)

target_sources(honey_protocol
    PRIVATE
        src/dummy.cc
    PUBLIC
        FILE_SET HEADERS
        BASE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include"
        FILES ${HONEY_PROTOCOL_HEADERS}
)

target_link_libraries(honey_protocol
    PUBLIC
        STDEXEC::stdexec
        Honey::Service
    PRIVATE
        Honey::Crypto
        Honey::Core
)

target_link_libraries(honey_protocol PUBLIC nlohmann_json::nlohmann_json)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
