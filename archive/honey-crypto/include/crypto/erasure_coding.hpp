#pragma once
#include <cstdint>
#include <expected>
#include <map>
#include <string>
#include <vector>

namespace Honey::Crypto::ErasureCode {

// 编码：将数据分割并编码成 N 个块，其中任意 K 个块可恢复数据
// 返回: vector of (N) blocks
auto encode(int K, int N, const std::vector<uint8_t>& data)
    -> std::expected<std::vector<std::vector<uint8_t>>, std::string>;

// 解码：从部分块恢复原始数据
// stripes: 包含 N 个元素的 vector，缺失的块为空 vector 或 nullptr
// 实际上我们需要知道每个块的索引，所以输入可以是 map<index, block>
auto decode(int K, int N, const std::map<int, std::vector<uint8_t>>& received_stripes)
    -> std::expected<std::vector<uint8_t>, std::string>;

}
