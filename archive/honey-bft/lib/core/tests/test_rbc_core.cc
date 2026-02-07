#include "core/rbc/rbc_core.hpp"
#include <algorithm>
#include <gtest/gtest.h>
#include <vector>

namespace Honey::BFT::RBC {

using Byte = std::byte;

class RBCCoreTest : public ::testing::Test {
protected:
    static constexpr int N = 4;
    static constexpr int f = 1;
    static constexpr int Leader = 0;
    static constexpr int MyPid = 1;
    static constexpr int Sid = 100;

    std::vector<Byte> original_message;
    Hash mock_root;
    std::vector<std::vector<Byte>> shards;

    void SetUp() override
    {
        original_message = { std::byte { 1 }, std::byte { 2 }, std::byte { 3 }, std::byte { 4 } };

        std::ranges::fill(mock_root, std::byte { 0xCC });

        for (int i = 0; i < N; ++i) {
            shards.push_back(original_message);
        }
    }

    RBCConfig make_config(int node_id = MyPid)
    {
        return RBCConfig {
            .session_id = Sid,
            .node_id = node_id,
            .total_nodes = N,
            .fault_tolerance = f,
            .leader_id = Leader
        };
    }

    RBCMessage make_val(int sender_id, int target_pid)
    {
        return RBCMessage {
            .type = RBCMessage::Type::Val,
            .sender = sender_id,
            .session_id = Sid,
            .payload = ValPayload {
                .root_hash = mock_root,
                .proof_index = static_cast<size_t>(target_pid),
                .merkle_path = {},
                .stripe = shards[target_pid] }
        };
    }

    RBCMessage make_echo(int sender_id)
    {
        return RBCMessage {
            .type = RBCMessage::Type::Echo,
            .sender = sender_id,
            .session_id = Sid,
            .payload = EchoPayload {
                .root_hash = mock_root,
                .proof_index = static_cast<size_t>(sender_id),
                .merkle_path = {},
                .stripe = shards[sender_id] }
        };
    }

    RBCMessage make_ready(int sender_id)
    {
        return RBCMessage {
            .type = RBCMessage::Type::Ready,
            .sender = sender_id,
            .session_id = Sid,
            .payload = ReadyPayload { .root_hash = mock_root }
        };
    }

    std::vector<Action> collect_actions(std::generator<Action> gen)
    {
        std::vector<Action> actions;
        for (auto action : gen) {
            actions.push_back(action);
        }
        return actions;
    }
};

TEST_F(RBCCoreTest, ReceivingValTriggersEcho)
{
    Core core(make_config());

    // Receive VAL from leader
    auto actions = collect_actions(core.on_msg(make_val(Leader, MyPid)));

    // Should not trigger any action immediately (ECHO broadcast happens at higher level)
    // The core just stores the stripe and waits for more messages
    EXPECT_TRUE(actions.empty());
}

TEST_F(RBCCoreTest, EchoQuorumTriggersBroadcastReady)
{
    Core core(make_config());

    // First receive VAL from leader
    auto actions1 = collect_actions(core.on_msg(make_val(Leader, MyPid)));
    EXPECT_TRUE(actions1.empty());

    // Receive N-f ECHOs (3 ECHOs including nodes 0, 2, 3)
    auto actions2 = collect_actions(core.on_msg(make_echo(0)));
    EXPECT_TRUE(actions2.empty());

    auto actions3 = collect_actions(core.on_msg(make_echo(2)));
    EXPECT_TRUE(actions3.empty());

    // The 3rd ECHO should trigger BroadcastReady
    auto actions4 = collect_actions(core.on_msg(make_echo(3)));
    ASSERT_EQ(actions4.size(), 1);
    EXPECT_EQ(actions4[0].type, Action::Type::BroadcastReady);
    EXPECT_EQ(actions4[0].root_hash, mock_root);
}

TEST_F(RBCCoreTest, ReadyQuorumTriggersDecode)
{
    Core core(make_config());

    // Setup: receive VAL and enough ECHOs to trigger READY
    collect_actions(core.on_msg(make_val(Leader, MyPid)));
    collect_actions(core.on_msg(make_echo(0)));
    collect_actions(core.on_msg(make_echo(2)));
    auto actions_ready = collect_actions(core.on_msg(make_echo(3)));
    ASSERT_EQ(actions_ready.size(), 1);
    EXPECT_EQ(actions_ready[0].type, Action::Type::BroadcastReady);

    // Now receive 2f+1 READYs (3 READYs from nodes 0, 2, 3)
    auto actions1 = collect_actions(core.on_msg(make_ready(0)));
    EXPECT_TRUE(actions1.empty());

    auto actions2 = collect_actions(core.on_msg(make_ready(2)));
    EXPECT_TRUE(actions2.empty());

    // The 3rd READY should trigger Decode
    auto actions3 = collect_actions(core.on_msg(make_ready(3)));
    ASSERT_EQ(actions3.size(), 1);
    EXPECT_EQ(actions3[0].type, Action::Type::Decode);
    EXPECT_EQ(actions3[0].root_hash, mock_root);
}

TEST_F(RBCCoreTest, ReadyAmplification)
{
    Core core(make_config());

    // Receive VAL from leader (provides 1 stripe)
    collect_actions(core.on_msg(make_val(Leader, MyPid)));

    // To decode later, we need at least N - 2f stripes (2 stripes for N=4, f=1)
    // Receive an ECHO to get another stripe
    collect_actions(core.on_msg(make_echo(2)));

    // Receive f+1 READYs (2 READYs) - should trigger BroadcastReady
    auto actions1 = collect_actions(core.on_msg(make_ready(2)));
    EXPECT_TRUE(actions1.empty());

    // The 2nd READY (f+1) should trigger BroadcastReady
    auto actions2 = collect_actions(core.on_msg(make_ready(3)));
    ASSERT_EQ(actions2.size(), 1);
    EXPECT_EQ(actions2[0].type, Action::Type::BroadcastReady);
    EXPECT_EQ(actions2[0].root_hash, mock_root);

    // Continue to 2f+1 READYs for Decode (now we have enough stripes)
    auto actions3 = collect_actions(core.on_msg(make_ready(0)));
    ASSERT_EQ(actions3.size(), 1);
    EXPECT_EQ(actions3[0].type, Action::Type::Decode);
}

TEST_F(RBCCoreTest, RejectsNonLeaderVal)
{
    Core core(make_config());

    // Non-leader sending VAL should be rejected
    auto actions1 = collect_actions(core.on_msg(make_val(2, MyPid)));
    EXPECT_TRUE(actions1.empty());

    // Valid VAL from leader
    auto actions2 = collect_actions(core.on_msg(make_val(Leader, MyPid)));
    EXPECT_TRUE(actions2.empty());

    // Proceed with normal flow
    collect_actions(core.on_msg(make_echo(0)));
    collect_actions(core.on_msg(make_echo(2)));
    auto actions_ready = collect_actions(core.on_msg(make_echo(3)));
    ASSERT_EQ(actions_ready.size(), 1);
    EXPECT_EQ(actions_ready[0].type, Action::Type::BroadcastReady);
}

TEST_F(RBCCoreTest, RejectsInconsistentRootHash)
{
    Core core(make_config());

    // Receive VAL with correct root
    collect_actions(core.on_msg(make_val(Leader, MyPid)));

    // Try to send VAL with different root - should be rejected
    Hash root2;
    std::fill(root2.begin(), root2.end(), std::byte { 0xDD });
    RBCMessage bad_val {
        .type = RBCMessage::Type::Val,
        .sender = Leader,
        .session_id = Sid,
        .payload = ValPayload {
            .root_hash = root2,
            .proof_index = static_cast<size_t>(MyPid),
            .merkle_path = {},
            .stripe = shards[MyPid],
        },
    };
    auto actions_bad = collect_actions(core.on_msg(bad_val));
    EXPECT_TRUE(actions_bad.empty());

    // Normal flow with correct root should work
    collect_actions(core.on_msg(make_echo(0)));
    collect_actions(core.on_msg(make_echo(2)));
    auto actions_ready = collect_actions(core.on_msg(make_echo(3)));
    ASSERT_EQ(actions_ready.size(), 1);
    EXPECT_EQ(actions_ready[0].type, Action::Type::BroadcastReady);
}

TEST_F(RBCCoreTest, DuplicateMessagesIgnored)
{
    Core core(make_config());

    collect_actions(core.on_msg(make_val(Leader, MyPid)));

    // Send same ECHO twice
    auto actions1 = collect_actions(core.on_msg(make_echo(0)));
    EXPECT_TRUE(actions1.empty());

    auto actions2 = collect_actions(core.on_msg(make_echo(0)));
    EXPECT_TRUE(actions2.empty());

    // Need 2 more unique ECHOs to reach N-f
    collect_actions(core.on_msg(make_echo(2)));
    auto actions_ready = collect_actions(core.on_msg(make_echo(3)));
    ASSERT_EQ(actions_ready.size(), 1);
    EXPECT_EQ(actions_ready[0].type, Action::Type::BroadcastReady);
}

TEST_F(RBCCoreTest, PartialEchoQuorumDoesNotTriggerReady)
{
    Core core(make_config());

    collect_actions(core.on_msg(make_val(Leader, MyPid)));

    // Only f ECHOs (1 ECHO, less than N-f=3 required)
    auto actions1 = collect_actions(core.on_msg(make_echo(2)));
    EXPECT_TRUE(actions1.empty());

    // Add one more, still not enough (2 < 3)
    auto actions2 = collect_actions(core.on_msg(make_echo(0)));
    EXPECT_TRUE(actions2.empty());

    // Now reach N-f threshold
    auto actions3 = collect_actions(core.on_msg(make_echo(3)));
    ASSERT_EQ(actions3.size(), 1);
    EXPECT_EQ(actions3[0].type, Action::Type::BroadcastReady);
}

} // namespace Honey::BFT::RBC
