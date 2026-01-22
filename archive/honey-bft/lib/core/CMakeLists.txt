add_library(honey_core STATIC)
add_library(Honey::Core ALIAS honey_core)

file(GLOB_RECURSE HONEY_CORE_HEADERS
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    include/*.h include/*.hpp include/**/*.h include/**/*.hpp
)

target_sources(honey_core
    PRIVATE
        src/rbc/rbc_core.cc
        src/coin/coin_core.cc
        src/ba/ba_core.cc

    PUBLIC
        FILE_SET HEADERS
        BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include
        FILES ${HONEY_CORE_HEADERS}
)

install(TARGETS honey_core
    EXPORT HBFTTargets
    FILE_SET HEADERS DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
