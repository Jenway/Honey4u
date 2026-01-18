cmake_minimum_required(VERSION 3.10)
project(HBFT CXX)
set(CMAKE_EXPORT_COMPILE_COMMANDS On)

include(FetchContent) # 引入 FetchContent 模块

set(FETCHCONTENT_FULLY_DISCONNECTED ON) 
# =============================================================
# ASIO (Standalone)
# =============================================================
FetchContent_Declare(
    asio
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG asio-1-24-0 # 锁定一个稳定版本
    GIT_SHALLOW TRUE
)

# 使用 make_available 让 asio 的 target 在全局可见
FetchContent_MakeAvailable(asio)
add_library(asio INTERFACE)
add_library(asio::asio ALIAS asio)

target_include_directories(asio INTERFACE
    ${asio_SOURCE_DIR}/asio/include
)

target_compile_definitions(asio INTERFACE
    ASIO_STANDALONE
)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CTest)
enable_testing()

add_subdirectory(lib/crypto)
add_subdirectory(lib/core)
