cmake_minimum_required(VERSION 3.28)

project(HBFT
    VERSION 0.1.0
    LANGUAGES C CXX
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS On)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(cmake/dependencies.cmake)

# include(cmake/compilers.cmake)

include(CTest)
enable_testing()

add_subdirectory(lib/crypto)
add_subdirectory(lib/core)


include(GNUInstallDirs)
install(EXPORT HBFTTargets
    FILE        HBFTTargets.cmake
    NAMESPACE   Honey::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/HBFT
)
