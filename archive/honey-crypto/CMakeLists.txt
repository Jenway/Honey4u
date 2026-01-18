# ========================================================
# Crypto Library CMakeLists.txt
# ========================================================
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 确保能找到 cmake/BuildBlst.cmake 和 cmake/BuildISAL.cmake
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

# 1. 查找系统依赖
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SECP256K1 REQUIRED libsecp256k1)

# 2. 引入 ExternalProject 构建脚本
include(BuildBlst) # 这里会定义 blst::blst
include(BuildISAL) # 这里会定义 ISAL::isal

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
    src/erasure_code.cc # 别忘了加上之前写的纠删码
    src/merkle_tree.cc
    src/utils.cc
)

add_library(Honey::Crypto ALIAS honey_crypto)

# 4. 配置头文件路径
target_include_directories(honey_crypto
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        src # 允许 .cc 文件找到 impl_common.hpp 等私有头文件
)

# 5. 链接依赖
target_link_libraries(honey_crypto
    PRIVATE
        OpenSSL::Crypto
        blst::blst         # 链接 ExternalProject 构建出的静态库
        ${SECP256K1_LIBRARIES}
        ISAL::isal         # 链接 ExternalProject 构建出的静态库
)


enable_testing()
add_subdirectory(tests)