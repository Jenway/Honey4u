include(ExternalProject)

find_program(NASM_PATH nasm)
if(NOT NASM_PATH)
    message(FATAL_ERROR "nasm not found! ISA-L requires nasm to build.")
endif()

set(ISAL_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/_deps/isal)
set(ISAL_INCLUDE_DIR ${ISAL_PREFIX}/include)
set(ISAL_LIB_DIR ${ISAL_PREFIX}/lib)
set(ISAL_STATIC_LIB ${ISAL_LIB_DIR}/libisal.a)

# --- 关键修改：手动创建目录 ---
# 在配置阶段就创建这个目录，防止 CMake 报错说路径不存在
# 此时它是空的，但在 Build 阶段 'make install' 会往里面放头文件
file(MAKE_DIRECTORY ${ISAL_INCLUDE_DIR})
# ---------------------------

ExternalProject_Add(isal_external
    PREFIX ${ISAL_PREFIX}
    GIT_REPOSITORY https://github.com/intel/isa-l.git
    GIT_TAG v2.31.0
    GIT_SHALLOW TRUE

    UPDATE_COMMAND ""

    # 必须在源码目录构建以支持 autogen.sh
    BUILD_IN_SOURCE 1

    CONFIGURE_COMMAND chmod +x autogen.sh && ./autogen.sh && ./configure --prefix=${ISAL_PREFIX} --libdir=${ISAL_LIB_DIR} --enable-static --disable-shared --with-pic
    
    BUILD_COMMAND make -j4
    
    INSTALL_COMMAND make install
    
    BUILD_BYPRODUCTS ${ISAL_STATIC_LIB}
)

add_library(ISAL::isal STATIC IMPORTED GLOBAL)

set_target_properties(ISAL::isal PROPERTIES
    IMPORTED_LOCATION ${ISAL_STATIC_LIB}
    # 这里引用的目录必须在配置时存在
    INTERFACE_INCLUDE_DIRECTORIES ${ISAL_INCLUDE_DIR}
)

add_dependencies(ISAL::isal isal_external)