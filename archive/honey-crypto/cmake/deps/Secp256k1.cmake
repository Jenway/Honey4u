include_guard(GLOBAL)

if(TARGET secp256k1::secp256k1)
    return()
endif()

pkg_check_modules(PC_SECP256K1 QUIET libsecp256k1)

find_path(SECP256K1_INCLUDE_DIR secp256k1.h
    HINTS ${PC_SECP256K1_INCLUDEDIR} ${PC_SECP256K1_INCLUDE_DIRS}
)
find_library(SECP256K1_LIBRARY
    NAMES secp256k1 libsecp256k1
    HINTS ${PC_SECP256K1_LIBDIR} ${PC_SECP256K1_LIBRARY_DIRS}
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Secp256k1
    REQUIRED_VARS SECP256K1_LIBRARY SECP256K1_INCLUDE_DIR
    VERSION_VAR PC_SECP256K1_VERSION
)

if(Secp256k1_FOUND)
    add_library(secp256k1::secp256k1 INTERFACE IMPORTED GLOBAL)
    target_include_directories(secp256k1::secp256k1 INTERFACE "${SECP256K1_INCLUDE_DIR}")
    target_link_libraries(secp256k1::secp256k1 INTERFACE "${SECP256K1_LIBRARY}")
endif()

mark_as_advanced(SECP256K1_INCLUDE_DIR SECP256K1_LIBRARY)
