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

    // --- Encoding Helpers ---

    /**
     * @brief 将数据填充成K的倍数，并添加长度前缀
     * @return (缓冲区, 每块大小)
     */
    std::pair<std::vector<Byte>, size_t> prepare_encode_buffer(BytesSpan data, int K)
    {
        size_t raw_len = data.size();
        size_t payload_len = LEN_PREFIX_SIZE + raw_len;
        size_t total_len = payload_len;
        if (total_len % K != 0) {
            total_len += K - (total_len % K);
        }
        size_t block_size = total_len / K;

        std::vector<Byte> buffer(total_len, Byte { 0 });
        write_u32_le(buffer.data(), static_cast<uint32_t>(raw_len));
        std::memcpy(buffer.data() + LEN_PREFIX_SIZE, data.data(), raw_len);

        return { std::move(buffer), block_size };
    }

    /**
     * @brief 准备编码的输入输出指针
     */
    void prepare_encode_pointers(
        std::span<Byte> buffer,
        size_t block_size,
        int K,
        std::vector<std::vector<Byte>>& result,
        std::vector<unsigned char*>& data_ptrs,
        std::vector<unsigned char*>& parity_ptrs)
    {
        // 填充前 K 个 (Systematic)
        for (int i = 0; i < K; ++i) {
            result[i].resize(block_size);
            std::memcpy(result[i].data(), &buffer[i * block_size], block_size);
            data_ptrs[i] = u8ptr(result[i].data());
        }

        // 预分配后 N-K 个 (Parity)
        int N = result.size();
        for (int i = 0; i < N - K; ++i) {
            result[K + i].resize(block_size);
            parity_ptrs[i] = u8ptr(result[K + i].data());
        }
    }

    /**
     * @brief 初始化编码表并执行编码
     */
    void perform_encode(
        size_t block_size,
        int K,
        int N,
        std::span<unsigned char*> data_ptrs,
        std::span<unsigned char*> parity_ptrs)
    {
        // 生成柯西矩阵
        std::vector<unsigned char> encode_matrix(N * K);
        gf_gen_cauchy1_matrix(encode_matrix.data(), N, K);

        // 获取校验部分的子矩阵
        unsigned char* parity_matrix = &encode_matrix[K * K];

        // 初始化 SIMD 查找表
        std::vector<unsigned char> g_tbls((N - K) * K * 32);
        ec_init_tables(K, N - K, parity_matrix, g_tbls.data());

        // 执行编码
        ec_encode_data(block_size, K, N - K, g_tbls.data(), data_ptrs.data(), parity_ptrs.data());
    }

    // --- Decoding Helpers ---

    /**
     * @brief 收集接收到的块并检查是否为恒等式（已是原始数据）
     * @return (是否为恒等式, 块索引)
     */
    std::pair<bool, std::vector<int>> collect_decode_shards(
        const std::map<int, std::vector<Byte>>& received_shards,
        int K,
        size_t block_size,
        std::vector<unsigned char*>& decode_ptrs)
    {
        bool is_identity = true;
        std::vector<int> decode_indexes;

        int count = 0;
        for (const auto& [idx, data] : received_shards) {
            if (count >= K)
                break;

            if (data.size() != block_size) {
                is_identity = false;
                continue;
            }

            decode_ptrs[count] = const_cast<unsigned char*>(u8ptr(data.data()));
            decode_indexes.push_back(idx);

            if (idx != count)
                is_identity = false;

            count++;
        }

        return { is_identity, decode_indexes };
    }

    /**
     * @brief 对接收到的块进行矩阵求逆并恢复原始数据
     * @return 错误码 或 空
     */
    std::expected<void, std::error_code> perform_matrix_inversion_decode(
        const std::vector<int>& decode_indexes,
        const std::vector<unsigned char*>& decode_ptrs,
        size_t block_size,
        int K,
        int N,
        std::vector<unsigned char*>& final_ptrs,
        std::vector<std::vector<Byte>>& recovered_buffers)
    {
        // 为恢复的数据分配空间
        recovered_buffers.resize(K);
        for (int i = 0; i < K; ++i) {
            recovered_buffers[i].resize(block_size);
            final_ptrs[i] = u8ptr(recovered_buffers[i].data());
        }

        // 构造编码矩阵
        std::vector<unsigned char> encode_matrix(N * K);
        gf_gen_cauchy1_matrix(encode_matrix.data(), N, K);

        // 构造解码矩阵（从接收到的行）
        std::vector<unsigned char> decode_matrix(K * K);
        for (int i = 0; i < K; i++) {
            int src_idx = decode_indexes[i];
            std::memcpy(&decode_matrix[i * K], &encode_matrix[src_idx * K], K);
        }

        // 求逆矩阵
        std::vector<unsigned char> invert_matrix(K * K);
        if (gf_invert_matrix(decode_matrix.data(), invert_matrix.data(), K) < 0) {
            return std::unexpected(std::make_error_code(std::errc::operation_not_permitted));
        }

        // 初始化解码表
        std::vector<unsigned char> g_tbls(K * K * 32);
        ec_init_tables(K, K, invert_matrix.data(), g_tbls.data());

        // 执行解码（通过逆矩阵乘法恢复原始数据）
        ec_encode_data(block_size, K, K, g_tbls.data(),
            const_cast<unsigned char**>(decode_ptrs.data()),
            final_ptrs.data());

        return {};
    }

    /**
     * @brief 从恢复的块中移除长度前缀和填充
     */
    std::expected<std::vector<Byte>, std::error_code> extract_original_data(
        std::span<unsigned char*> final_ptrs,
        int K,
        size_t block_size)
    {
        // 拼接所有块
        std::vector<Byte> buffer;
        buffer.reserve(K * block_size);
        for (int i = 0; i < K; ++i) {
            const Byte* ptr = reinterpret_cast<const Byte*>(final_ptrs[i]);
            buffer.insert(buffer.end(), ptr, ptr + block_size);
        }

        // 提取长度
        if (buffer.size() < LEN_PREFIX_SIZE)
            return std::unexpected(std::make_error_code(std::errc::bad_message));

        uint32_t original_len = read_u32_le(buffer.data());
        if (original_len > buffer.size() - LEN_PREFIX_SIZE)
            return std::unexpected(std::make_error_code(std::errc::bad_message));

        // 提取原始数据
        std::vector<Byte> output(original_len);
        std::memcpy(output.data(), buffer.data() + LEN_PREFIX_SIZE, original_len);

        return output;
    }

} // namespace

auto encode(const Context& ctx, BytesSpan data)
    -> std::expected<std::vector<std::vector<Byte>>, std::error_code>
{
    int K = ctx.K();
    int N = ctx.N();

    // 参数验证
    if (data.size() > UINT32_MAX) {
        return std::unexpected(std::make_error_code(std::errc::file_too_large));
    }

    // 准备输入缓冲区
    auto [buffer, block_size] = prepare_encode_buffer(data, K);

    // 准备输入输出指针
    std::vector<std::vector<Byte>> result(N);
    std::vector<unsigned char*> data_ptrs(K);
    std::vector<unsigned char*> parity_ptrs(N - K);

    prepare_encode_pointers(buffer, block_size, K, result, data_ptrs, parity_ptrs);

    // 执行编码
    perform_encode(block_size, K, N, data_ptrs, parity_ptrs);

    return result;
}

auto decode(const Context& ctx, const std::map<int, std::vector<Byte>>& received_shards)
    -> std::expected<std::vector<Byte>, std::error_code>
{
    int K = ctx.K();
    int N = ctx.N();

    // 参数验证
    if (received_shards.size() < static_cast<size_t>(K)) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    // 获取块大小
    size_t block_size = received_shards.begin()->second.size();
    if (block_size == 0)
        return std::vector<Byte> {};

    // 验证所有块大小一致
    for (const auto& [_, shard] : received_shards) {
        if (shard.size() != block_size) {
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        }
    }

    // 收集块指针并检查是否为恒等式
    std::vector<unsigned char*> decode_ptrs(K);
    auto [is_identity, decode_indexes] = collect_decode_shards(
        received_shards, K, block_size, decode_ptrs);

    // 准备最终指针
    std::vector<unsigned char*> final_ptrs(K);
    std::vector<std::vector<Byte>> recovered_buffers;

    if (is_identity) {
        // Fast Path：已是原始数据，直接使用
        final_ptrs = decode_ptrs;
    } else {
        // Slow Path：需要矩阵求逆恢复
        auto result = perform_matrix_inversion_decode(
            decode_indexes, decode_ptrs, block_size, K, N, final_ptrs, recovered_buffers);
        if (!result) {
            return std::unexpected(result.error());
        }
    }

    // 从恢复的块中提取原始数据
    return extract_original_data(final_ptrs, K, block_size);
}

// --- Context Implementation ---

std::expected<Context, std::error_code> Context::create(int K, int N)
{
    if (K <= 0 || N <= K) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    // 生成柯西矩阵
    std::vector<unsigned char> encode_matrix(N * K);
    gf_gen_cauchy1_matrix(encode_matrix.data(), N, K);

    // 初始化编码表（用于编码）
    unsigned char* parity_matrix = &encode_matrix[K * K];
    std::vector<unsigned char> parity_g_tbls((N - K) * K * 32);
    ec_init_tables(K, N - K, parity_matrix, parity_g_tbls.data());

    // 初始化解码表（用于解码）
    // 这里用单位矩阵作为示例，实际解码时会根据接收到的块索引重新计算
    std::vector<unsigned char> decode_matrix(K * K);
    for (int i = 0; i < K; ++i) {
        for (int j = 0; j < K; ++j) {
            decode_matrix[i * K + j] = (i == j) ? 1 : 0;
        }
    }
    std::vector<unsigned char> decode_g_tbls(K * K * 32);
    ec_init_tables(K, K, decode_matrix.data(), decode_g_tbls.data());

    return Context(K, N, std::move(encode_matrix), std::move(parity_g_tbls), std::move(decode_g_tbls));
}

} // namespace Honey::Crypto::ErasureCode
