#include "crypto/erasure_code.hpp"
#include <gtest/gtest.h>
#include <map>
#include <random>
#include <vector>

namespace Honey::Crypto::ErasureCode {

class ErasureCodeTest : public ::testing::Test {
protected:
    // 辅助函数：生成随机数据
    std::vector<Byte> random_bytes(size_t len)
    {
        std::vector<Byte> res(len);
        std::mt19937 rng(42); // 固定种子保证测试确定性
        std::uniform_int_distribution<uint16_t> dist(0, 255);
        for (size_t i = 0; i < len; ++i) {
            res[i] = static_cast<Byte>(dist(rng));
        }
        return res;
    }

    // 辅助函数：比较两个 Byte vector
    void expect_bytes_eq(const std::vector<Byte>& a, const std::vector<Byte>& b)
    {
        ASSERT_EQ(a.size(), b.size());
        for (size_t i = 0; i < a.size(); ++i) {
            EXPECT_EQ(a[i], b[i]) << "Mismatch at index " << i;
        }
    }
};

// 测试 1: 基础编码与完整解码 (K=2, N=4)
TEST_F(ErasureCodeTest, BasicRoundTrip)
{
    int K = 2;
    int N = 4;
    auto data = random_bytes(100); // 100 bytes

    // Encode
    auto shards_res = encode(K, N, data);
    ASSERT_TRUE(shards_res.has_value());
    auto shards = *shards_res;
    ASSERT_EQ(shards.size(), N);

    // Decode with ALL shards
    std::map<int, std::vector<Byte>> received;
    for (int i = 0; i < N; ++i)
        received[i] = shards[i];

    auto decoded_res = decode(K, N, received);
    ASSERT_TRUE(decoded_res.has_value());
    expect_bytes_eq(data, *decoded_res);
}

// 测试 2: 最小恢复 (只用 K 个任意分片)
TEST_F(ErasureCodeTest, RecoverFromMinimum)
{
    int K = 4;
    int N = 10;
    auto data = random_bytes(1024); // 1KB

    auto shards = *encode(K, N, data);

    // 挑选 K 个不连续的分片，例如索引 1, 3, 5, 9
    std::map<int, std::vector<Byte>> received;
    received[1] = shards[1];
    received[3] = shards[3];
    received[5] = shards[5];
    received[9] = shards[9];

    ASSERT_EQ(received.size(), K);

    auto decoded_res = decode(K, N, received);
    ASSERT_TRUE(decoded_res.has_value());
    expect_bytes_eq(data, *decoded_res);
}

// 测试 3: Identity Fast Path (前 K 个分片)
// 这测试代码中 `is_identity` 的优化路径，不应该触发矩阵求逆
TEST_F(ErasureCodeTest, IdentityFastPath)
{
    int K = 3;
    int N = 5;
    auto data = random_bytes(333);

    auto shards = *encode(K, N, data);

    std::map<int, std::vector<Byte>> received;
    for (int i = 0; i < K; ++i)
        received[i] = shards[i];

    auto decoded_res = decode(K, N, received);
    ASSERT_TRUE(decoded_res.has_value());
    expect_bytes_eq(data, *decoded_res);
}

// 测试 4: 极小数据和 Padding 边界
TEST_F(ErasureCodeTest, SmallDataAndPadding)
{
    int K = 4;
    int N = 8;

    // Case A: 空数据
    // encode 应该处理空数据（通常变成 LengthPrefix=0 + Padding）
    // 或者你的实现如果 check size > 0 可能报错。假设允许空。
    auto empty_res = encode(K, N, {});
    if (empty_res) {
        std::map<int, std::vector<Byte>> recv;
        for (int i = 0; i < K; ++i)
            recv[i] = (*empty_res)[i];
        auto dec = decode(K, N, recv);
        ASSERT_TRUE(dec.has_value());
        EXPECT_TRUE(dec->empty());
    }

    // Case B: 只有 1 字节
    auto one_byte = random_bytes(1);
    auto shards = *encode(K, N, one_byte);

    // 丢掉前 K-1 个，只用最后一个和 parity
    std::map<int, std::vector<Byte>> recv_mixed;
    for (int i = 0; i < K; ++i)
        recv_mixed[N - 1 - i] = shards[N - 1 - i];

    auto dec_one = decode(K, N, recv_mixed);
    ASSERT_TRUE(dec_one.has_value());
    expect_bytes_eq(one_byte, *dec_one);
}

// 测试 5: 错误处理
TEST_F(ErasureCodeTest, Errors)
{
    int K = 3;
    int N = 5;
    auto data = random_bytes(100);
    auto shards = *encode(K, N, data);

    // 1. 分片不足
    std::map<int, std::vector<Byte>> not_enough;
    not_enough[0] = shards[0];
    not_enough[1] = shards[1]; // 只给 2 个，需要 3 个
    EXPECT_FALSE(decode(K, N, not_enough).has_value());

    // 2. 分片大小不一致
    std::map<int, std::vector<Byte>> bad_size;
    for (int i = 0; i < K; ++i)
        bad_size[i] = shards[i];
    bad_size[0].pop_back(); // 破坏大小
    EXPECT_FALSE(decode(K, N, bad_size).has_value());

    // 3. 无效参数 (K > N)
    EXPECT_FALSE(encode(5, 3, data).has_value());
}

}  // namespace Honey::Crypto::ErasureCode