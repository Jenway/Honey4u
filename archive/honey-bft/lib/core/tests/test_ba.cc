#include "core/ba/binary_agreement.hpp"
#include "core/ba/messages.hpp"
#include "core/common.hpp"
#include "utils_simple_task.hpp"
#include <deque>
#include <gtest/gtest.h>
#include <vector>

namespace Honey::BFT::BA {

template <typename T>
using TaskT = InlineTask<T>;

struct MockTransport {
    std::shared_ptr<std::vector<Message>> broadcasts = std::make_shared<std::vector<Message>>();

    TaskT<void> broadcast(Message msg)
    {
        broadcasts->push_back(msg);
        co_return;
    }
};

struct MockCoin {
    int fixed_value = 0; // 控制硬币结果

    TaskT<int> get_coin(int /*round*/)
    {
        co_return fixed_value;
    }
};

struct MockStream {
    std::deque<Message> messages;

    TaskT<std::optional<Message>> next()
    {
        if (messages.empty())
            co_return std::nullopt;
        auto msg = messages.front();
        messages.pop_front();
        co_return msg;
    }
};

class BinaryAgreementTest : public ::testing::Test {
public:
    MockTransport transport;
    MockCoin coin;
    MockStream stream;

protected:
    static constexpr int N = 4;
    static constexpr int f = 1;
    static constexpr int MyPid = 0;
    static constexpr int LeaderPid = 0;
    static constexpr SystemContext system_ctx { .N = N, .f = f };

    static Message bval(int sender, int r, int v)
    {
        return Message {
            .sender = sender,
            .session_id = 1,
            .payload = ValPayload { .round = r, .value = v }
        };
    }

    static Message aux(int sender, int r, int v)
    {
        return Message {
            .sender = sender,
            .session_id = 1,
            .payload = AuxPayload { .round = r, .value = v }
        };
    }
};

// -----------------------------------------------------------------------------
// Test Case 1: 0-Input 一致性 (Happy Path)
// 所有人都输入 0，应该在第 0 轮直接决定 0
// -----------------------------------------------------------------------------
TEST_F(BinaryAgreementTest, AgreementOnZero)
{
    BinaryAgreement<TaskT, MockTransport, MockCoin> ba(
        system_ctx,
        1, // session id
        MyPid, // my node id
        LeaderPid, // leader id
        transport,
        coin);

    // 2. 剧本构造
    // 阶段 A: BVAL
    // 我启动后会广播 BVAL(0)。
    // 然后我收到其他人的 BVAL(0)，这会触发 bin_values = {0}
    stream.messages.push_back(bval(1, 0, 0));
    stream.messages.push_back(bval(2, 0, 0));

    // 阶段 B: AUX
    // 当 bin_values 非空，我会广播 AUX(0)。
    // 然后我收到其他人的 AUX(0)。
    stream.messages.push_back(aux(1, 0, 0));
    stream.messages.push_back(aux(2, 0, 0));

    // 3. 运行
    auto task = ba.run(0, stream); // 我的输入是 0
    int result = task.get();

    // 4. 验证
    EXPECT_EQ(result, 0);

    // 验证网络行为
    // 应该至少广播了 BVAL(0, 0) 和 AUX(0, 0)
    ASSERT_GE(transport.broadcasts->size(), 2);

    // 检查发出的消息内容
    auto msg1 = transport.broadcasts->at(0);
    auto* p1 = std::get_if<ValPayload>(&msg1.payload);
    ASSERT_TRUE(p1);
    EXPECT_EQ(p1->value, 0); // BVAL(0)

    auto msg2 = transport.broadcasts->at(1);
    auto* p2 = std::get_if<AuxPayload>(&msg2.payload);
    ASSERT_TRUE(p2);
    EXPECT_EQ(p2->value, 0); // AUX(0)
}

// -----------------------------------------------------------------------------
// Test Case 2: 1-Input 一致性
// 所有人都输入 1，应该决定 1
// -----------------------------------------------------------------------------
TEST_F(BinaryAgreementTest, AgreementOnOne)
{
    BinaryAgreement<TaskT, MockTransport, MockCoin> ba(
        system_ctx,
        1, // session id
        MyPid, // my node id
        LeaderPid, // leader id
        transport,
        coin);

    coin.fixed_value = 1;

    // 模拟大家都在推 1
    stream.messages.push_back(bval(1, 0, 1));
    stream.messages.push_back(bval(2, 0, 1));
    stream.messages.push_back(aux(1, 0, 1));
    stream.messages.push_back(aux(2, 0, 1));

    auto task = ba.run(1, stream); // 我的输入是 1
    int result = task.get();

    EXPECT_EQ(result, 1);
}

// -----------------------------------------------------------------------------
// Test Case 3: 冲突与硬币 (Contention)
// 我输入 0，但网络上 0 和 1 都有，导致 AUX 阶段收到 {0, 1}
// 需要硬币来打破僵局
// -----------------------------------------------------------------------------
TEST_F(BinaryAgreementTest, CoinFlipDecides)
{
    BinaryAgreement<TaskT, MockTransport, MockCoin> ba(
        system_ctx,
        1, // session id
        MyPid, // my node id
        LeaderPid, // leader id
        transport,
        coin);

    // 设置硬币结果：让第 0 轮硬币返回 1
    // 这样如果发生冲突，大家应该下一轮倾向于 1
    coin.fixed_value = 1;

    // --- Round 0 ---

    // 1. BVAL 阶段：网络很混乱，我收到了 0 和 1 的 BVAL
    // 我输入 0 -> 我发 BVAL(0)
    // 收到 quorum BVAL(0) -> 我加 0 到 bin_values，发 AUX(0) (假设逻辑优先处理自己的值)
    stream.messages.push_back(bval(1, 0, 0));
    stream.messages.push_back(bval(2, 0, 0));

    // 同时我也收到了 2f+1 个 BVAL(1) -> 我加 1 到 bin_values
    // 注意：需要确保 Core 逻辑允许 bin_values 包含多个值
    stream.messages.push_back(bval(1, 0, 1));
    stream.messages.push_back(bval(2, 0, 1));

    // 2. AUX 阶段：我发了 AUX(0)，但我收到了别人的 AUX(1) 和 AUX(0)
    // 导致收到的 vals 集合为 {0, 1}
    // 构造混合的 AUX 消息流:
    // 节点 1 发 AUX(0), 节点 2 发 AUX(1), 节点 3 发 AUX(1)
    stream.messages.push_back(aux(1, 0, 0));
    stream.messages.push_back(aux(2, 0, 1));
    stream.messages.push_back(aux(3, 0, 1));

    // 此时 Core 逻辑：
    // vals = {0, 1}
    // s = Coin.get(0) = 1
    // 因为 vals != {s}, 所以 estimate_next = s = 1
    // 也就是虽然这轮没达成一致，但下一轮大家都应该选 1

    // --- Round 1 ---

    // 在下一轮，大家都变成了 estimate=1
    // 所以网络上全是 BVAL(1, 1) 和 AUX(1, 1)
    stream.messages.push_back(bval(1, 1, 1));
    stream.messages.push_back(bval(2, 1, 1));
    stream.messages.push_back(aux(1, 1, 1));
    stream.messages.push_back(aux(2, 1, 1));

    // 运行
    auto task = ba.run(0, stream); // 我初始输入 0
    int result = task.get();

    // 验证：
    // 虽然我初始是 0，但因为硬币是 1，且第 0 轮冲突了，第 1 轮应该达成 1
    EXPECT_EQ(result, 1);

    // 检查是否进行了两轮广播
    // Round 0: BVAL(0), AUX(0)
    // Round 1: BVAL(1), AUX(1)
    // 至少 4 条广播
    ASSERT_GE(transport.broadcasts->size(), 4);
}

} // namespace Honey::BFT::BA
