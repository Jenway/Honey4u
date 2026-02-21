#include "core/common.hpp"
#include "protocol/acs/acs.hpp"
#include "protocol/acs/events.hpp"
#include <deque>
#include <exec/task.hpp>
#include <format>
#include <gtest/gtest.h>
#include <stdexec/execution.hpp>
#include <string>
#include <vector>

namespace Honey::BFT::ACS {

// Use exec::task
template <typename T>
using TaskT = exec::task<T>;

// -----------------------------------------------------------------------------
// 1. Mocks
// -----------------------------------------------------------------------------

struct MockRBCService {
    std::vector<std::string> call_log;

    void start_rbc(int instance_id, std::span<const Byte> input)
    {
        if (input.empty()) {
            call_log.push_back(std::format("start_rbc({}, empty)", instance_id));
        } else {
            call_log.push_back(std::format("start_rbc({}, input)", instance_id));
        }
    }

    void dispatch_rbc_msg(int instance_id, int sender_id, const std::vector<Byte>&)
    {
        call_log.push_back(std::format("dispatch_rbc({}, {})", instance_id, sender_id));
    }
};

struct MockBAService {
    std::vector<std::string> call_log;

    void start_ba(int instance_id, int input_val)
    {
        call_log.push_back(std::format("start_ba({}, val={})", instance_id, input_val));
    }

    void dispatch_ba_msg(int instance_id, int sender_id, const std::vector<Byte>&)
    {
        call_log.push_back(std::format("dispatch_ba({}, {})", instance_id, sender_id));
    }
};

struct MockEventStream {
    std::deque<ACSEvent> events;

    TaskT<std::optional<ACSEvent>> next()
    {
        if (events.empty()) {
            co_return std::nullopt;
        }
        auto ev = std::move(events.front());
        events.pop_front();
        co_return ev;
    }
};

// -----------------------------------------------------------------------------
// 2. Test Fixture
// -----------------------------------------------------------------------------

class ACSTest : public ::testing::Test {
protected:
    static constexpr int N = 4;
    static constexpr int f = 1;
    static constexpr int MyPid = 0;
    static constexpr SystemContext sys_ctx { .N = N, .f = f };

    MockRBCService rbc_svc;
    MockBAService ba_svc;
    MockEventStream stream;

    // 辅助：生成 fake data
    std::vector<Byte> make_data(int val)
    {
        return { static_cast<Byte>(val) };
    }
};

// -----------------------------------------------------------------------------
// Test Case: Happy Path (Common Subset 达成)
// -----------------------------------------------------------------------------
TEST_F(ACSTest, RunsCorrectlyOnHappyPath)
{
    // TODO: 重构为使用 ProtocolManager 的集成测试
    // 旧的 Mock 架构已废弃
    GTEST_SKIP() << "Temporarily disabled due to architecture refactoring";

    /*
    // 1. Setup ACS
    ACS acs(0, MyPid, protocol_manager);  // session_id=0

    // 2. 构造剧本 (Scenario)
    // 场景：节点 0, 1, 2 的 RBC 较快完成，BA 均决定 1。
    // 节点 3 的 RBC 较慢，导致 ACS 触发补 0 逻辑，BA 3 决定 0。

    // [Event 1-3]: RBC 0, 1, 2 完成
    stream.events.push_back(RbcDoneEvent { 0, make_data(100) });
    stream.events.push_back(RbcDoneEvent { 1, make_data(101) });
    stream.events.push_back(RbcDoneEvent { 2, make_data(102) });

    // [Event 4-6]: 对应的 BA 0, 1, 2 完成，决定 1 (Yes)
    // 注意：在真实的 ACS 中，RbcDone 会触发 start_ba(1)。
    // 这里我们模拟 Service 层反馈回来的 BaDone 事件。
    stream.events.push_back(BaDoneEvent { 0, 1 }); // BA 0 decides 1
    stream.events.push_back(BaDoneEvent { 1, 1 }); // BA 1 decides 1
    stream.events.push_back(BaDoneEvent { 2, 1 }); // BA 2 decides 1
    // 此时收到 3 个 (N-f) Yes，ACS 应该内部触发 Vote 0 logic，即 start_ba(3, 0)

    // [Event 7]: BA 3 完成，决定 0 (No)
    // 即使 RBC 3 还没完，BA 3 也可以决定 0（因为被大家放弃了）
    stream.events.push_back(BaDoneEvent { 3, 0 });

    // 此时所有 4 个 BA 都结束了 (0,1,2=1, 3=0)。
    // ACS 应该收集 RBC 0,1,2 的数据并返回。

    // 3. Run
    std::vector<Byte> my_input = make_data(999);
    auto task = acs.run(my_input, stream);

    // 4. Verify Output
    auto result_opt = stdexec::sync_wait(std::move(task));
    ASSERT_TRUE(result_opt.has_value());
    auto result = std::get<0>(*result_opt);

    // 预期结果：包含 RBC 0, 1, 2 的数据。
    // 注意：get_output 的顺序取决于 map 遍历顺序 (key 0, 1, 2)，通常是排序的。
    ASSERT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], make_data(100));
    EXPECT_EQ(result[1], make_data(101));
    EXPECT_EQ(result[2], make_data(102));

    // 5. Verify Logic Flow (通过 Mock Logs)

    // 检查 RBC 启动
    // Node 0 (MyPid) 应该带输入启动，其他不带
    // 检查顺序可能不固定，但这里是 for loop 0..N
    EXPECT_EQ(rbc_svc.call_log[0], "start_rbc(0, input)");
    EXPECT_EQ(rbc_svc.call_log[1], "start_rbc(1, empty)");

    // 检查 BA 启动逻辑
    // RBC 0, 1, 2 完成 -> 应该触发 start_ba(x, 1)
    bool started_ba_0_yes = false;
    bool started_ba_3_no = false;

    for (const auto& log : ba_svc.call_log) {
        if (log == "start_ba(0, val=1)")
            started_ba_0_yes = true;
        // 关键点：检查是否触发了补 0
        // 当 BA 0,1,2 决定 1 后，ACS 应该自动对剩下的 BA 3 发起 0 的投票
        if (log == "start_ba(3, val=0)")
            started_ba_3_no = true;
    }

    EXPECT_TRUE(started_ba_0_yes) << "Should start BA 0 with 1 after RBC 0 done";
    EXPECT_TRUE(started_ba_3_no) << "Should start BA 3 with 0 after threshold reached";
    */
}

// -----------------------------------------------------------------------------
// Test Case: Network Routing
// 验证网络消息是否被正确分发给 RBC 或 BA
// -----------------------------------------------------------------------------
TEST_F(ACSTest, RoutesMessagesCorrectly)
{
    // TODO: 重构为使用 ProtocolManager 的集成测试
    GTEST_SKIP() << "Temporarily disabled due to architecture refactoring";

    /*
    ACS acs(0, MyPid, protocol_manager);

    // 构造一些网络消息事件
    // RBC Msg: sender=2, instance=1
    stream.events.emplace_back(NetworkMsgEvent {
        .sender = 2,
        .instance_id = 1,
        .is_rbc = true,
        .payload = { std::byte { 0xAA } } });

    // BA Msg: sender=3, instance=0
    stream.events.emplace_back(NetworkMsgEvent {
        .sender = 3,
        .instance_id = 0,
        .is_rbc = false,
        .payload = { std::byte { 0xBB } } });

    // 运行，由于没有完成事件，run 会在 stream 耗尽后返回空 vector
    auto task = acs.run({}, stream);
    stdexec::sync_wait(std::move(task));

    // 验证路由
    // RBC Svc 应该收到 instance 1 的消息
    bool rbc_routed = false;
    for (const auto& log : rbc_svc.call_log) {
        if (log == "dispatch_rbc(1, 2)")
            rbc_routed = true;
    }
    EXPECT_TRUE(rbc_routed);

    // BA Svc 应该收到 instance 0 的消息
    bool ba_routed = false;
    for (const auto& log : ba_svc.call_log) {
        if (log == "dispatch_ba(0, 3)")
            ba_routed = true;
    }
    EXPECT_TRUE(ba_routed);
    */
}

} // namespace Honey::BFT::ACS
