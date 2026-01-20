add_library(honey_crypto STATIC)
add_library(Honey::Crypto ALIAS honey_crypto)

file(GLOB_RECURSE HONEY_CRYPTO_HEADERS
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    include/*.h include/*.hpp include/**/*.h include/**/*.hpp
)

target_sources(honey_crypto
    PRIVATE
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
    PUBLIC
        FILE_SET HEADERS
        BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include
        FILES ${HONEY_CRYPTO_HEADERS}
)

target_compile_features(honey_crypto PUBLIC cxx_std_23)

target_link_libraries(honey_crypto
    PRIVATE
        OpenSSL::Crypto
        blst::blst
        ${SECP256K1_LIBRARIES}
        ISAL::isal
)

install(TARGETS honey_crypto
    EXPORT HBFTTargets
    FILE_SET HEADERS DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
