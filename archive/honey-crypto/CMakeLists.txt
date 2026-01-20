add_library(honey_crypto STATIC)
add_library(Honey::Crypto ALIAS honey_crypto)

# Public headers to expose to users
set(HONEY_CRYPTO_PUBLIC_HEADERS
    # Foundation layer
    include/crypto/common.hpp
    include/crypto/error.hpp
    include/crypto/merkle_tree.hpp
    include/crypto/erasure_code.hpp
    include/crypto/ecdsa.hpp
    # BLS12-381 curve primitives
    include/crypto/blst/Scalar.hpp
    include/crypto/blst/P1.hpp
    include/crypto/blst/P2.hpp
    # Threshold cryptography (user-facing APIs)
    include/crypto/threshold/types.hpp
    include/crypto/threshold/key_gen.hpp
    include/crypto/threshold/tbls.hpp
    include/crypto/threshold/tpke.hpp
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
        FILES ${HONEY_CRYPTO_PUBLIC_HEADERS}
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
