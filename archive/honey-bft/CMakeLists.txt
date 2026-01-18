cmake_minimum_required(VERSION 3.14)
project(HBFT CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS On)

include(CTEst)
enable_testing()
include(FetchContent)
include(GNUInstallDirs)

set(FETCHCONTENT_FULLY_DISCONNECTED ON)

FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG asio-1-24-0
    GIT_SHALLOW TRUE
)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
)

FetchContent_MakeAvailable(asio)
add_library(asio INTERFACE)
add_library(asio::asio ALIAS asio)
target_include_directories(asio INTERFACE ${asio_SOURCE_DIR}/asio/include)
target_compile_definitions(asio INTERFACE ASIO_STANDALONE)

add_subdirectory(lib/crypto)
add_subdirectory(lib/core)

install(EXPORT HBFTTargets
    FILE        HBFTTargets.cmake
    NAMESPACE   Honey::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/HBFT
)
