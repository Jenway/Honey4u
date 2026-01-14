set(CMAKE_EXPORT_COMPILE_COMMANDS On)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SECP256K1 REQUIRED libsecp256k1)

include(BuildBlst)
add_blst_library(libs/blst)


add_library(honey_crypto STATIC
    src/ecdsa.cc
    src/tbls.cc
    src/tpke.cc
    src/blst.cc
    src/utils.cc
)

add_library(Honey::Crypto ALIAS honey_crypto)

target_include_directories(honey_crypto
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(honey_crypto
    PUBLIC
        OpenSSL::Crypto
        blst::blst
        ${SECP256K1_LIBRARIES}
)


# ========================================================
# 测试
# ========================================================
add_subdirectory(tests)
