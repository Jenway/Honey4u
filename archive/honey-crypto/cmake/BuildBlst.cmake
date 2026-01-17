include(ExternalProject)

# 定义安装路径
set(BLST_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/_deps/blst)
set(BLST_INCLUDE_DIR ${BLST_PREFIX}/include)
set(BLST_LIB_DIR ${BLST_PREFIX}/lib)
set(BLST_STATIC_LIB ${BLST_LIB_DIR}/libblst.a)

# --- 关键：预先创建 include 目录 ---
# 防止 CMake 在配置阶段报错 "INTERFACE_INCLUDE_DIRECTORIES includes non-existent path"
file(MAKE_DIRECTORY ${BLST_INCLUDE_DIR})

ExternalProject_Add(blst_external
    PREFIX ${BLST_PREFIX}
    
    # 选项 A: 自动从 GitHub 下载 (推荐，版本固定更安全)
    GIT_REPOSITORY https://github.com/supranational/blst.git
    GIT_TAG v0.3.15  # 锁定一个稳定版本
    GIT_SHALLOW TRUE
    
    UPDATE_COMMAND ""

    # 必须在源码内构建，因为 build.sh 假定在当前目录工作
    BUILD_IN_SOURCE 1

    # BLST 不需要 configure 步骤
    CONFIGURE_COMMAND ""

    # 构建命令
    # -fPIC 是为了防止链接到共享库时报错 (即使你的库是 static，如果有上层应用是 shared，也需要 PIC)
    # 如果是 Windows，这里可能需要改为 build.bat
    BUILD_COMMAND ./build.sh -fPIC

    # 安装命令 (手动复制)
    # BLST 的头文件在 bindings/ 目录下，库文件在根目录下
    INSTALL_COMMAND 
        ${CMAKE_COMMAND} -E make_directory ${BLST_LIB_DIR} &&
        ${CMAKE_COMMAND} -E copy libblst.a ${BLST_LIB_DIR} &&
        ${CMAKE_COMMAND} -E copy bindings/blst.h ${BLST_INCLUDE_DIR} &&
        ${CMAKE_COMMAND} -E copy bindings/blst_aux.h ${BLST_INCLUDE_DIR}

    # 指定产物用于依赖检查
    BUILD_BYPRODUCTS ${BLST_STATIC_LIB}
)

# 创建 IMPORTED 目标
add_library(blst::blst STATIC IMPORTED GLOBAL)

set_target_properties(blst::blst PROPERTIES
    IMPORTED_LOCATION ${BLST_STATIC_LIB}
    INTERFACE_INCLUDE_DIRECTORIES ${BLST_INCLUDE_DIR}
)

# 确保在使用前已经构建完成
add_dependencies(blst::blst blst_external)