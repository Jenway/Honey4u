# 启用测试
enable_testing()

# 下载并配置 GoogleTest
include(FetchContent)
FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.14.0
)
FetchContent_MakeAvailable(googletest)

# ========================================================
# 测试辅助宏 (减少重复代码)
# ========================================================
macro(add_hbft_test TEST_NAME SOURCE_FILE)
    add_executable(${TEST_NAME} ${SOURCE_FILE})
    target_link_libraries(${TEST_NAME}
        PRIVATE
            hbft_crypto        # 链接你的核心库
            GTest::gtest
            GTest::gtest_main
    )
    # 因为 hbft_crypto 已经是 PUBLIC include，这里不需要额外指定 include 目录
    # 除非你有测试专用的头文件在 tests/ 目录下
endmacro()

# ========================================================
# 定义测试目标
# ========================================================

# ECDSA 测试
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/test_ecdsa.cc)
    add_hbft_test(ecdsa_test test_ecdsa.cc)
endif()

# TBLS (Threshold Signature) 测试
add_hbft_test(tbls_test test_tbls.cc)

# TPKE (Threshold Encryption) 测试
add_hbft_test(tpke_test test_tpke.cc)

# ========================================================
# 注册测试 (让 ctest 命令能找到它们)
# ========================================================
include(GoogleTest)

if(TARGET ecdsa_test)
    gtest_discover_tests(ecdsa_test)
endif()
if(TARGET tbls_test)
    gtest_discover_tests(tbls_test)
endif()
if(TARGET tpke_test)
    gtest_discover_tests(tpke_test)
endif()