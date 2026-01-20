#include "crypto/erasure_code.hpp"
#include <gtest/gtest.h>
#include <map>
#include <random>
#include <vector>

namespace Honey::Crypto::ErasureCode {

class ErasureCodeTest : public ::testing::Test {
protected:
    // 测试参数
    int K = 4;
    int N = 10;
    std::shared_ptr<Context> ctx;

    void SetUp() override
    {
        auto ctx_res = Context::create(K, N);
        ASSERT_TRUE(ctx_res.has_value());
        ctx = std::make_shared<Context>(std::move(*ctx_res));
    }

    std::vector<Byte> random_bytes(size_t len)
    {
        std::vector<Byte> res(len);
        std::mt19937 rng(42);
        std::uniform_int_distribution<uint16_t> dist(0, 255);
        for (size_t i = 0; i < len; ++i) {
            res[i] = static_cast<Byte>(dist(rng));
        }
        return res;
    }

    void expect_bytes_eq(const std::vector<Byte>& a, const std::vector<Byte>& b)
    {
        ASSERT_EQ(a.size(), b.size());
        for (size_t i = 0; i < a.size(); ++i) {
            EXPECT_EQ(a[i], b[i]) << "Mismatch at index " << i;
        }
    }
};

// 测试 1: 基础编码与完整解码
TEST_F(ErasureCodeTest, BasicRoundTrip)
{
    auto data = random_bytes(100); // 100 bytes

    // Encode
    auto shards_res = encode(*ctx, data);
    ASSERT_TRUE(shards_res.has_value());
    auto shards = *shards_res;
    ASSERT_EQ(shards.size(), N);

    // Decode with ALL shards
    std::map<int, std::vector<Byte>> received;
    for (int i = 0; i < N; ++i)
        received[i] = shards[i];

    auto decoded_res = decode(*ctx, received);
    ASSERT_TRUE(decoded_res.has_value());
    expect_bytes_eq(data, *decoded_res);
}

// 测试 2: 最小恢复 (只用 K 个任意分片)
TEST_F(ErasureCodeTest, RecoverFromMinimum)
{
    auto data = random_bytes(1024); // 1KB

    auto shards = *encode(*ctx, data);

    // 挑选 K 个不连续的分片，例如索引 1, 3, 5, 9
    std::map<int, std::vector<Byte>> received;
    received[1] = shards[1];
    received[3] = shards[3];
    received[5] = shards[5];
    received[9] = shards[9];

    ASSERT_EQ(received.size(), K);

    auto decoded_res = decode(*ctx, received);
    ASSERT_TRUE(decoded_res.has_value());
    expect_bytes_eq(data, *decoded_res);
}

// 测试 3: Identity Fast Path (前 K 个分片)
// 这测试代码中 `is_identity` 的优化路径，不应该触发矩阵求逆
TEST_F(ErasureCodeTest, IdentityFastPath)
{
    auto data = random_bytes(333);

    auto shards = *encode(*ctx, data);

    std::map<int, std::vector<Byte>> received;
    for (int i = 0; i < K; ++i)
        received[i] = shards[i];

    auto decoded_res = decode(*ctx, received);
    ASSERT_TRUE(decoded_res.has_value());
    expect_bytes_eq(data, *decoded_res);
}

// 测试 4: 极小数据和 Padding 边界
TEST_F(ErasureCodeTest, SmallDataAndPadding)
{
    // Case A: 空数据
    // encode 应该处理空数据（通常变成 LengthPrefix=0 + Padding）
    // 或者你的实现如果 check size > 0 可能报错。假设允许空。
    auto empty_res = encode(*ctx, {});
    if (empty_res) {
        std::map<int, std::vector<Byte>> recv;
        for (int i = 0; i < K; ++i)
            recv[i] = (*empty_res)[i];
        auto dec = decode(*ctx, recv);
        ASSERT_TRUE(dec.has_value());
        EXPECT_TRUE(dec->empty());
    }

    // Case B: 只有 1 字节
    auto one_byte = random_bytes(1);
    auto shards = *encode(*ctx, one_byte);

    // 丢掉前 K-1 个，只用最后一个和 parity
    std::map<int, std::vector<Byte>> recv_mixed;
    for (int i = 0; i < K; ++i)
        recv_mixed[N - 1 - i] = shards[N - 1 - i];

    auto dec_one = decode(*ctx, recv_mixed);
    ASSERT_TRUE(dec_one.has_value());
    expect_bytes_eq(one_byte, *dec_one);
}

// 测试 5: 错误处理
TEST_F(ErasureCodeTest, Errors)
{
    auto data = random_bytes(100);
    auto shards = *encode(*ctx, data);

    // 1. 分片不足
    std::map<int, std::vector<Byte>> not_enough;
    not_enough[0] = shards[0];
    not_enough[1] = shards[1]; // 只给 2 个，需要 K 个
    EXPECT_FALSE(decode(*ctx, not_enough).has_value());

    // 2. 分片大小不一致
    std::map<int, std::vector<Byte>> bad_size;
    for (int i = 0; i < K; ++i)
        bad_size[i] = shards[i];
    bad_size[0].pop_back(); // 破坏大小
    EXPECT_FALSE(decode(*ctx, bad_size).has_value());

    // 3. 无效参数 (K > N)
    EXPECT_FALSE(Context::create(5, 3).has_value());
}

} // namespace Honey::Crypto::ErasureCode
