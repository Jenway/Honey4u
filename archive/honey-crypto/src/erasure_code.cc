#include "crypto/erasure_code.hpp"
#include <cstdint> 
#include <cstring> 
#include <isa-l/erasure_code.h> 
#include <utility> 
#include <vector> 

namespace Honey::Crypto::ErasureCode {

namespace {

    // --- Length Prefix Helpers ---
    constexpr size_t LEN_PREFIX_SIZE = 4;

    void write_u32_le(Byte* buf, uint32_t val)
    {
        uint8_t* p = u8ptr(buf);
        p[0] = static_cast<uint8_t>(val);
        p[1] = static_cast<uint8_t>(val >> 8);
        p[2] = static_cast<uint8_t>(val >> 16);
        p[3] = static_cast<uint8_t>(val >> 24);
    }

    uint32_t read_u32_le(const Byte* buf)
    {
        const uint8_t* p = u8ptr(buf);
        return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
    }

} // namespace

auto encode(int K, int N, BytesSpan data)
    -> std::expected<std::vector<std::vector<Byte>>, std::error_code>
{
    // ISA-L 没有 K<=256 的硬性限制，但通常纠删码不会设得特别大
    if (K <= 0 || N <= K) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }
    if (data.size() > UINT32_MAX) {
        return std::unexpected(std::make_error_code(std::errc::file_too_large));
    }

    // 1. Padding 逻辑 (保持不变)
    size_t raw_len = data.size();
    size_t payload_len = LEN_PREFIX_SIZE + raw_len;
    size_t total_len = payload_len;
    if (total_len % K != 0) {
        total_len += K - (total_len % K);
    }
    size_t block_size = total_len / K;

    // 准备大的连续内存作为输入 buffer
    std::vector<Byte> buffer(total_len, Byte { 0 });
    write_u32_le(buffer.data(), static_cast<uint32_t>(raw_len));
    std::memcpy(buffer.data() + LEN_PREFIX_SIZE, data.data(), raw_len);

    // 2. 准备输出容器
    // ISA-L 需要我们将所有指针（包括原始数据和校验数据）准备好
    std::vector<std::vector<Byte>> result(N);
    std::vector<unsigned char*> data_ptrs(K);
    std::vector<unsigned char*> parity_ptrs(N - K);

    // 填充前 K 个 (Systematic)
    for (int i = 0; i < K; ++i) {
        result[i].resize(block_size);
        std::memcpy(result[i].data(), &buffer[i * block_size], block_size);
        data_ptrs[i] = u8ptr(result[i].data());
    }

    // 预分配后 N-K 个 (Parity)
    for (int i = 0; i < N - K; ++i) {
        result[K + i].resize(block_size);
        parity_ptrs[i] = u8ptr(result[K + i].data());
    }

    // 3. ISA-L 编码核心
    // 生成柯西矩阵 (Cauchy Matrix)
    std::vector<unsigned char> encode_matrix(N * K);
    gf_gen_cauchy1_matrix(encode_matrix.data(), N, K);

    // ISA-L 的 ec_encode_data 只需要矩阵中关于“校验部分”的子矩阵
    // 即 encode_matrix 的第 K 行到第 N-1 行
    // 矩阵存储是行优先，所以偏移量是 K * K
    unsigned char* parity_matrix = &encode_matrix[K * K];

    // 初始化 SIMD 查找表 (32 bytes per element)
    std::vector<unsigned char> g_tbls((N - K) * K * 32);
    ec_init_tables(K, N - K, parity_matrix, g_tbls.data());

    // 执行编码！(这是最快的一步)
    ec_encode_data(block_size, K, N - K, g_tbls.data(), data_ptrs.data(), parity_ptrs.data());

    return result;
}

auto decode(int K, int N, const std::map<int, std::vector<Byte>>& received_shards)
    -> std::expected<std::vector<Byte>, std::error_code>
{
    if (received_shards.size() < static_cast<size_t>(K)) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    size_t block_size = received_shards.begin()->second.size();
    if (block_size == 0)
        return std::vector<Byte> {};

    // 1. 整理接收到的块
    std::vector<unsigned char*> decode_ptrs(K);
    std::vector<int> decode_indexes(K); // 记录我们用了哪些块的索引

    // 检查是否已经是完整的原始数据 (Fast Path)
    bool is_identity = true;
    int count = 0;

    // 用 map 自动排序的特性，我们按顺序取前 K 个
    for (const auto& [idx, data] : received_shards) {
        if (data.size() != block_size)
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));

        // 注意：const cast 是为了适配 ISA-L API，实际 decode 不会修改 input
        decode_ptrs[count] = const_cast<unsigned char*>(u8ptr(data.data()));
        decode_indexes[count] = idx;

        if (idx != count)
            is_identity = false;

        if (++count == K)
            break;
    }

    // 存放恢复结果的容器
    std::vector<std::vector<Byte>> recovered_buffers;
    std::vector<unsigned char*> final_ptrs(K);

    if (is_identity) {
        // Fast Path: 直接使用接收到的指针
        final_ptrs = decode_ptrs;
    } else {
        // Slow Path: 需要矩阵求逆
        recovered_buffers.resize(K);
        for (int i = 0; i < K; ++i) {
            recovered_buffers[i].resize(block_size);
            // 默认指向恢复缓冲区
            final_ptrs[i] = u8ptr(recovered_buffers[i].data());
        }

        // --- 矩阵构造开始 ---
        std::vector<unsigned char> encode_matrix(N * K);
        gf_gen_cauchy1_matrix(encode_matrix.data(), N, K);

        // 构造“解码矩阵”：它是编码矩阵中对应接收到的行组成的子矩阵
        std::vector<unsigned char> decode_matrix(K * K);
        for (int i = 0; i < K; i++) {
            int src_idx = decode_indexes[i];
            // 复制第 src_idx 行
            std::memcpy(&decode_matrix[i * K], &encode_matrix[src_idx * K], K);
        }

        // 求逆矩阵
        std::vector<unsigned char> invert_matrix(K * K);
        if (gf_invert_matrix(decode_matrix.data(), invert_matrix.data(), K) < 0) {
            return std::unexpected(std::make_error_code(std::errc::operation_not_permitted)); // 矩阵不可逆? 理论上 Cauchy 矩阵总是可逆
        }

        // 初始化解码表
        std::vector<unsigned char> g_tbls(K * K * 32);
        ec_init_tables(K, K, invert_matrix.data(), g_tbls.data());

        // 执行解码
        // 注意：这里我们实际上是把“部分数据”通过“逆矩阵”乘法还原成“原始数据”
        // ISA-L 的 decode 实际上就是一种 encode 操作
        ec_encode_data(block_size, K, K, g_tbls.data(), decode_ptrs.data(), final_ptrs.data());
        // --- 矩阵构造结束 ---
    }

    // 2. 拼接与 Unpadding (保持不变)
    std::vector<Byte> buffer;
    buffer.reserve(K * block_size);
    for (int i = 0; i < K; ++i) {
        const Byte* ptr = reinterpret_cast<const Byte*>(final_ptrs[i]);
        buffer.insert(buffer.end(), ptr, ptr + block_size);
    }

    if (buffer.size() < LEN_PREFIX_SIZE)
        return std::unexpected(std::make_error_code(std::errc::bad_message));
    uint32_t original_len = read_u32_le(buffer.data());
    if (original_len > buffer.size() - LEN_PREFIX_SIZE)
        return std::unexpected(std::make_error_code(std::errc::bad_message));

    std::vector<Byte> output(original_len);
    std::memcpy(output.data(), buffer.data() + LEN_PREFIX_SIZE, original_len);

    return output;
}

}  // namespace Honey::Crypto::ErasureCode