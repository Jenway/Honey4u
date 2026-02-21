include(FetchContent)

if(WIN32)
    set(_CACHE_DIR "$ENV{USERPROFILE}/.cache")
else()
    set(_CACHE_DIR "$ENV{HOME}/.cache")
endif()

# Configure CPM cache
if(NOT DEFINED CPM_SOURCE_CACHE)
    set(CPM_SOURCE_CACHE "${_CACHE_DIR}/CPM" CACHE PATH "CPM source cache")
endif()

# Configure FetchContent cache
set(FETCHCONTENT_SOURCE_DIR_core "${_CACHE_DIR}/cmake/sources" CACHE PATH "FetchContent source cache")
set(FETCHCONTENT_BASE_DIR "${_CACHE_DIR}/cmake/deps" CACHE PATH "FetchContent build/install cache")
set(FETCHCONTENT_QUIET OFF)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)

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

find_package(nlohmann_json REQUIRED CONFIG)

if(BUILD_TESTING)
    find_package(doctest REQUIRED CONFIG)
endif()

# Find system dependencies
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SECP256K1 REQUIRED libsecp256k1)
find_package(spdlog REQUIRED CONFIG)
find_package(fmt REQUIRED CONFIG)

# Include custom build scripts
include(BuildBlst)
include(BuildISAL)
include(BuildAsio)
