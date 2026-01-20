#pragma once

#include <expected>
#include <map>
#include <system_error>
#include <vector>

#include "crypto/common.hpp"

namespace Honey::Crypto::ErasureCode {

/**
 * @brief 纠删码编码 (Reed-Solomon)
 *
 * 采用 "Length-Prefix" 方案处理变长数据:
 * 1. 在数据头部写入 4 字节的原始数据长度 (Little-Endian)。
 * 2. 补零直到总长度是 K 的倍数。
 * 3. 进行 RS 编码。
 *
 * @param K 数据块数量 (阈值)
 * @param N 总块数 (N >= K)
 * @param data 任意长度的二进制数据
 */
[[nodiscard]]
auto encode(int K, int N, BytesSpan data)
    -> std::expected<std::vector<std::vector<Byte>>, std::error_code>;

/**
 * @brief 纠删码解码
 *
 * @param received_shards 接收到的分片 (Index -> Data)。至少需要 K 个。
 * @return 原始数据 (自动去除 Padding 和 Length Prefix)
 */
[[nodiscard]]
auto decode(int K, int N, const std::map<int, std::vector<Byte>>& received_shards)
    -> std::expected<std::vector<Byte>, std::error_code>;

} // namespace Honey::Crypto::ErasureCode
