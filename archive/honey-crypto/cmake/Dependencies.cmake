include_guard(GLOBAL)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)
find_package(PkgConfig REQUIRED)

include(Secp256k1)
include(Blst)
include(ISAL)

find_package(spdlog REQUIRED CONFIG)
find_package(fmt REQUIRED CONFIG)

if(BUILD_TESTING)
    find_package(doctest REQUIRED CONFIG)
endif()
