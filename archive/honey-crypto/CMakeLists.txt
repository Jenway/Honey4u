add_library(honey_crypto STATIC)
add_library(Honey::Crypto ALIAS honey_crypto)

file(GLOB_RECURSE HONEY_CRYPTO_HEADERS
    RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}
    "include/*.h" "include/*.hpp" "include/**/*.h" "include/**/*.hpp"
)

target_compile_features(honey_crypto PUBLIC cxx_std_23)
target_include_directories(honey_crypto PRIVATE src)

target_sources(honey_crypto
    PRIVATE
        src/blst/ops.cc
        src/blst/scalar.cc
        src/blst/p1.cc
        src/blst/p2.cc
        src/aes.cc
        src/ecdsa.cc
        src/threshold/tbls.cc
        src/threshold/tpke.cc
        src/erasure_code.cc
        src/merkle_tree.cc
        src/utils.cc
    PUBLIC
        FILE_SET HEADERS
        BASE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/include"
        FILES ${HONEY_CRYPTO_HEADERS}
)

target_link_libraries(honey_crypto
    PRIVATE
        OpenSSL::Crypto
        blst::blst
        ISAL::isal
        ${SECP256K1_LIBRARIES}
)

install(TARGETS honey_crypto
    EXPORT HBFTTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    FILE_SET HEADERS DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

# Generate BLST ABI header
set(BLST_ABI_HPP "${CMAKE_BINARY_DIR}/generated/blst_abi_config.hpp")

add_executable(blst_abi_probe "${CMAKE_CURRENT_SOURCE_DIR}/cmake/blst_abi_probe.c")
set_source_files_properties(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/blst_abi_probe.c"
    PROPERTIES LANGUAGE C
)
target_link_libraries(blst_abi_probe PRIVATE blst::blst)

add_custom_command(
    OUTPUT "${BLST_ABI_HPP}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/generated"
    COMMAND "$<TARGET_FILE:blst_abi_probe>" "${BLST_ABI_HPP}"
    DEPENDS blst_abi_probe
    COMMENT "Generating BLST ABI configuration header"
    VERBATIM
)

add_custom_target(blst_abi ALL DEPENDS "${BLST_ABI_HPP}")
add_dependencies(honey_crypto blst_abi)

# Add generated headers to include path
target_include_directories(honey_crypto PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/generated>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)

install(FILES "${BLST_ABI_HPP}" DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
