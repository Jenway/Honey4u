#include "core/coin/common_coin.hpp"
#include "core/coin/messages.hpp"
#include "utils_simple_task.hpp"
#include <deque>
#include <gtest/gtest.h>
#include <optional>

namespace Honey::BFT::Coin {
template <typename T>
using TaskT = InlineTask<T>;

using Byte = std::byte;
using BytesSpan = std::span<const Byte>;

namespace {

    struct MockTransport {
        std::shared_ptr<std::vector<Message>> broadcasts = std::make_shared<std::vector<Message>>();

        TaskT<void> broadcast(Message msg)
        {
            broadcasts->push_back(msg);
            co_return;
        }
    };

    struct MockCryptoSvc {
        TaskT<std::optional<Signature>> async_combine_signatures(
            std::span<const PartialSignature> shares)
        {
            std::array<limb_t, LIMB_COUNT> combined;
            std::ranges::fill(combined, 0);

            if (!shares.empty()) {
                // 仅作演示，拷贝第一个 share 作为基底
                combined = shares[0].value;
            }
            co_return combined;
        }

        uint8_t hash_to_bit(const SignatureShare& signature)
        {
            if (!signature.empty() && static_cast<uint8_t>(signature[0]) % 2 == 0) {
                return 0;
            }
            return 1;
        }

        TaskT<SignatureShare> async_sign_share(BytesSpan /*message*/)
        {
            std::array<limb_t, LIMB_COUNT> sig;
            std::ranges::fill(sig, 0xAA);
            co_return sig;
        }
        TaskT<bool> async_verify_signature(const Signature&, BytesSpan)
        {
            co_return true;
        }

        TaskT<bool> async_verify_share(const SignatureShare&, BytesSpan, int)
        {
            co_return true;
        }
    };

    struct MockMessageStream {
        std::deque<Message> messages;
        size_t current_index = 0;

        TaskT<std::optional<Message>> next()
        {
            if (messages.empty()) {
                co_return std::nullopt;
            }
            auto msg = messages.front();
            messages.pop_front();
            co_return msg;
        }
    };

    static_assert(CoinTransceiver<MockTransport>);
    static_assert(CryptoService<MockCryptoSvc>);
    static_assert(AsyncStreamOf<MockMessageStream, Message>);
} // namespace

class CommonCoinTest : public ::testing::Test {
protected:
    static constexpr int N = 4;
    static constexpr int f = 1;
    static constexpr int MyPid = 1;
    static constexpr int Sid = 200;
    MockTransport transport;
    MockCryptoSvc crypto;

    Message make_share(int sender, int round, uint64_t val_byte)
    {
        std::array<limb_t, LIMB_COUNT> sig;
        std::ranges::fill(sig, 0);
        sig[0] = val_byte;
        return Message {
            .sender = sender,
            .session_id = Sid,
            .payload = SharePayload { .round = round, .sig = sig }
        };
    }
};

// Test1 Happy Path
TEST_F(CommonCoinTest, DeliversOnQuorum)
{
    CommonCoin<MockTransport, MockCryptoSvc, InlineTask> coin(Sid, MyPid, N, f, transport, crypto);
    MockMessageStream stream;

    // 1. 预先填充数据 (3个 share，满足 f+1=2 或 N-f=3)
    // 假设 CryptoMock 只需要非空 share 即可
    stream.messages.push_back(make_share(0, 1, 0x01)); // 奇数 -> hash_to_bit = 1
    stream.messages.push_back(make_share(2, 1, 0x01));
    stream.messages.push_back(make_share(3, 1, 0x01));

    // run in the background
    auto run_task = coin.run(stream);
    // 确保 run 正常结束 (捕获异常)
    run_task.get();

    // 3. 获取结果
    // 此时 CommonCoin 内部状态应该已经更新 (results_[1].completed = true)
    // 所以 get_coin 会走 Fast Path，立即返回结果
    auto coin_task = coin.get_coin(1);
    uint8_t result = coin_task.get();

    EXPECT_EQ(result, 1);
}

// ---------------------------------------------------------------------------
// Test 2: 交互测试 - 先请求，后收到数据
// ---------------------------------------------------------------------------
TEST_F(CommonCoinTest, BroadcastsAndWaits)
{
    CommonCoin<MockTransport, MockCryptoSvc, TaskT> coin(Sid, MyPid, N, f, transport, crypto);

    MockMessageStream empty_stream;
    coin.run(empty_stream).get();

    // 因为没有 share，它会：
    // 1. 签名并广播 (MockTransport 记录)
    // 2. 挂起等待 RoundResultAwaiter
    auto coin_task = coin.get_coin(1);

    // 验证副作用：是否广播了自己的 share
    ASSERT_EQ(transport.broadcasts->size(), 1);
    EXPECT_EQ((*transport.broadcasts)[0].sender, MyPid);

    // 注入缺失的数据
    MockMessageStream fill_stream;
    fill_stream.messages.push_back(make_share(0, 1, 0x01));
    fill_stream.messages.push_back(make_share(2, 1, 0x01));
    fill_stream.messages.push_back(make_share(3, 1, 0x01));

    coin.run(fill_stream).get();

    // 阶段 4: 现在 coin_task 应该已经完成了
    uint8_t result = coin_task.get();
    EXPECT_EQ(result, 1);
}

} // namespace Honey::BFT::Coin
