add_library(honey_core STATIC)
add_library(Honey::Core ALIAS honey_core)

file(GLOB_RECURSE HONEY_CORE_HEADERS
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    "include/*.h" "include/*.hpp" "include/**/*.h" "include/**/*.hpp"
)

file(GLOB_RECURSE HONEY_CORE_SOURCES
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    "src/*.cc" "src/**/*.cc"
)

target_compile_features(honey_core PUBLIC cxx_std_23)

target_sources(honey_core
    PRIVATE ${HONEY_CORE_SOURCES}
    PUBLIC
        FILE_SET HEADERS
        BASE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include"
        FILES ${HONEY_CORE_HEADERS}
)

install(TARGETS honey_core
    EXPORT HBFTTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    FILE_SET HEADERS DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
