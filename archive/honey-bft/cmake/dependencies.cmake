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
