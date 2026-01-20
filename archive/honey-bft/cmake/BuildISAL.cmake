include(ExternalProject)

find_program(NASM_PATH nasm)
if(NOT NASM_PATH)
    message(FATAL_ERROR "nasm not found! ISA-L requires nasm to build.")
endif()

set(ISAL_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/_deps/isal)
set(ISAL_INCLUDE_DIR ${ISAL_PREFIX}/include)
set(ISAL_LIB_DIR ${ISAL_PREFIX}/lib)
set(ISAL_STATIC_LIB ${ISAL_LIB_DIR}/libisal.a)

file(MAKE_DIRECTORY ${ISAL_INCLUDE_DIR})

ExternalProject_Add(isal_external
    PREFIX ${ISAL_PREFIX}
    GIT_REPOSITORY https://github.com/intel/isa-l.git
    GIT_TAG v2.31.0
    GIT_SHALLOW TRUE

    UPDATE_COMMAND ""

    BUILD_IN_SOURCE 1

    CONFIGURE_COMMAND chmod +x autogen.sh && ./autogen.sh && ./configure --prefix=${ISAL_PREFIX} --libdir=${ISAL_LIB_DIR} --enable-static --disable-shared --with-pic

    BUILD_COMMAND make -j4

    INSTALL_COMMAND make install

    BUILD_BYPRODUCTS ${ISAL_STATIC_LIB}
)

add_library(ISAL::isal STATIC IMPORTED GLOBAL)

set_target_properties(ISAL::isal PROPERTIES
    IMPORTED_LOCATION ${ISAL_STATIC_LIB}
    INTERFACE_INCLUDE_DIRECTORIES ${ISAL_INCLUDE_DIR}
)

add_dependencies(ISAL::isal isal_external)
