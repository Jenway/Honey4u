set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SECP256K1 REQUIRED libsecp256k1)

include(BuildBlst)
include(BuildISAL)

add_library(honey_crypto STATIC
    src/blst/scalar.cc
    src/blst/p1.cc
    src/blst/p1_affine.cc
    src/blst/p2.cc
    src/blst/p2_affine.cc
    src/blst/pt.cc
    src/aes.cc
    src/ecdsa.cc
    src/tbls.cc
    src/tpke.cc
    src/erasure_code.cc
    src/merkle_tree.cc
    src/utils.cc
)

add_library(Honey::Crypto ALIAS honey_crypto)

target_include_directories(honey_crypto
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        src
)

target_link_libraries(honey_crypto
    PRIVATE
        OpenSSL::Crypto
        blst::blst
        ${SECP256K1_LIBRARIES}
        ISAL::isal
)

install(TARGETS honey_crypto
    EXPORT HBFTTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
