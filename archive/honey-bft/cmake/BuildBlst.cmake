include(ExternalProject)

set(BLST_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/_deps/blst)
set(BLST_INCLUDE_DIR ${BLST_PREFIX}/include)
set(BLST_LIB_DIR ${BLST_PREFIX}/lib)
set(BLST_STATIC_LIB ${BLST_LIB_DIR}/libblst.a)

file(MAKE_DIRECTORY ${BLST_INCLUDE_DIR})

ExternalProject_Add(blst_external
    PREFIX ${BLST_PREFIX}

    GIT_REPOSITORY https://github.com/supranational/blst.git
    GIT_TAG v0.3.15
    GIT_SHALLOW TRUE

    UPDATE_COMMAND ""

    BUILD_IN_SOURCE 1

    CONFIGURE_COMMAND ""

    BUILD_COMMAND ./build.sh -fPIC

    INSTALL_COMMAND
        ${CMAKE_COMMAND} -E make_directory ${BLST_LIB_DIR} &&
        ${CMAKE_COMMAND} -E copy libblst.a ${BLST_LIB_DIR} &&
        ${CMAKE_COMMAND} -E copy bindings/blst.h ${BLST_INCLUDE_DIR} &&
        ${CMAKE_COMMAND} -E copy bindings/blst_aux.h ${BLST_INCLUDE_DIR}

    BUILD_BYPRODUCTS ${BLST_STATIC_LIB}
)

add_library(blst::blst STATIC IMPORTED GLOBAL)

set_target_properties(blst::blst PROPERTIES
    IMPORTED_LOCATION ${BLST_STATIC_LIB}
    INTERFACE_INCLUDE_DIRECTORIES ${BLST_INCLUDE_DIR}
)

add_dependencies(blst::blst blst_external)
