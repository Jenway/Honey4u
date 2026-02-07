include(FetchContent)

# Asio
FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG asio-1-24-0
    GIT_SHALLOW TRUE
)

FetchContent_MakeAvailable(asio)
if(NOT TARGET asio)
    add_library(asio INTERFACE)
    if(NOT TARGET asio::asio)
        add_library(asio::asio ALIAS asio)
    endif()
endif()

file(
  DOWNLOAD
  https://github.com/cpm-cmake/CPM.cmake/releases/download/v0.40.8/CPM.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/cmake/CPM.cmake
  EXPECTED_HASH SHA256=78ba32abdf798bc616bab7c73aac32a17bbd7b06ad9e26a6add69de8f3ae4791
)

include(${CMAKE_CURRENT_BINARY_DIR}/cmake/CPM.cmake)

CPMAddPackage(
  NAME stdexec
  GITHUB_REPOSITORY NVIDIA/stdexec
  GIT_TAG main
    OPTIONS
    "BUILD_TESTING OFF"
    "STDEXEC_BUILD_TESTS OFF"
    "STDEXEC_BUILD_EXAMPLES OFF"
)

# spdlog
CPMAddPackage(
  NAME spdlog
  GITHUB_REPOSITORY gabime/spdlog
  GIT_TAG v1.17.0
  OPTIONS
    "SPDLOG_BUILD_SHARED OFF"
)

# GoogleTest
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
)
FetchContent_MakeAvailable(googletest)

# OpenSSL & Secp256k1
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SECP256K1 REQUIRED libsecp256k1)

include(BuildBlst)
include(BuildISAL)
