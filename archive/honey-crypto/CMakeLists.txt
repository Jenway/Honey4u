cmake_minimum_required(VERSION 3.28)

project(honey-crypto
    VERSION 0.1.0
    LANGUAGES C CXX
    HOMEPAGE_URL "https://github.com/jenway/honey-crypto"
)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)

list(APPEND CMAKE_MODULE_PATH
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake"
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/deps"
)
include(Dependencies)

add_subdirectory(lib/merkle)

add_library(honey_crypto STATIC)
add_library(Honey::Crypto ALIAS honey_crypto)

target_compile_features(honey_crypto
    PUBLIC cxx_std_23
)

target_include_directories(honey_crypto
    PRIVATE
        src
        "${CMAKE_CURRENT_SOURCE_DIR}/lib"
)

file(GLOB_RECURSE HONEY_CRYPTO_SOURCES
    "src/*.cc" "src/**/*.cc"
)
file(GLOB_RECURSE HONEY_CRYPTO_INTERNAL_HEADERS
    "src/*.h" "src/*.hpp" "src/**/*.h" "src/**/*.hpp"
)

target_sources(honey_crypto
    PRIVATE
        ${HONEY_CRYPTO_SOURCES}
        ${HONEY_CRYPTO_INTERNAL_HEADERS}
        $<TARGET_OBJECTS:honey_crypto_c_merkle>
)

file(GLOB_RECURSE HONEY_CRYPTO_PUBLIC_HEADERS CONFIGURE_DEPENDS
    "include/*.h"
    "include/*.hpp"
    "include/**/*.h"
    "include/**/*.hpp"
)

target_sources(honey_crypto
    PUBLIC
        FILE_SET HEADERS
        BASE_DIRS include
        FILES ${HONEY_CRYPTO_PUBLIC_HEADERS}
)

target_link_libraries(honey_crypto
    PUBLIC
    PRIVATE
        OpenSSL::Crypto
        blst::blst
        ISAL::isal
        secp256k1::secp256k1
        spdlog::spdlog
        fmt::fmt
)

include(CTest)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

set(BLST_ABI_HPP "${CMAKE_BINARY_DIR}/generated/blst_abi_config.hpp")

add_executable(blst_abi_probe "cmake/blst_abi_probe.c")
set_source_files_properties("cmake/blst_abi_probe.c" PROPERTIES LANGUAGE C)
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

target_include_directories(honey_crypto
    PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/generated>"
)

install(TARGETS honey_crypto
    EXPORT HoneyCryptoTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    FILE_SET HEADERS DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(FILES "${BLST_ABI_HPP}"
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/crypto
)

install(EXPORT HoneyCryptoTargets
    FILE HoneyCryptoTargets.cmake
    NAMESPACE Honey::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/HoneyCrypto
)

include(CMakePackageConfigHelpers)
configure_package_config_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/HoneyCryptoConfig.cmake.in"
    "${CMAKE_CURRENT_BINARY_DIR}/HoneyCryptoConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/HoneyCrypto
)

write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/HoneyCryptoConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/HoneyCryptoConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/HoneyCryptoConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/HoneyCrypto
)
