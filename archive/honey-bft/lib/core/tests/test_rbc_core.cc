#include "core/rbc/messages.hpp"
#include "core/rbc/rbc_core.hpp"

#include "test_rbc_core_utils.hpp"
#include <gtest/gtest.h>
#include <variant>
#include <vector>

namespace Honey::BFT::RBC {

class RBCCoreTest : public ::testing::Test {
protected:
    void SetUp() override { }
    void TearDown() override { }

    auto create_core()
    {
        return RBCCore({ .session_id = kSessionId, .node_id = pid, .total_nodes = N, .fault_tolerance = f, .leader_id = leader });
    }

public:
    const int N = 4;
    const int f = 1;
    const int leader = 0;
    const int pid = 1;
};

TEST_F(RBCCoreTest, LeaderValBroadcastsEcho)
{
    auto core = create_core();
    const auto root = make_hash(1);
    const auto effects = collect_effects(core.handle_message(make_val(leader, root, 0xAA)));

    ASSERT_EQ(effects.size(), 1U);
    EXPECT_EQ(effects.front().type, Effect::Type::Broadcast);
    ASSERT_TRUE(effects.front().msg.has_value());
    EXPECT_TRUE(std::holds_alternative<EchoPayload>(effects.front().msg->payload));
    const auto& echo = std::get<EchoPayload>(effects.front().msg->payload);
    EXPECT_EQ(echo.root_hash, root);
    ASSERT_EQ(echo.stripe.size(), 1U);
    EXPECT_EQ(echo.stripe[0], static_cast<Byte>(0xAA));
}

TEST_F(RBCCoreTest, ReadySentAfterEchoThreshold)
{
    auto core = create_core();

    const auto root = make_hash(2);
    collect_effects(core.handle_message(make_val(RBCCoreTest::leader, root, 0x10)));

    const auto echo2_effects = collect_effects(core.handle_message(make_echo(2, root, 0x20)));
    EXPECT_TRUE(echo2_effects.empty());

    const auto echo3_effects = collect_effects(core.handle_message(make_echo(3, root, 0x30)));
    ASSERT_EQ(echo3_effects.size(), 1U);
    EXPECT_EQ(echo3_effects.front().type, Effect::Type::Broadcast);
    ASSERT_TRUE(echo3_effects.front().msg.has_value());
    EXPECT_TRUE(std::holds_alternative<ReadyPayload>(echo3_effects.front().msg->payload));
}

TEST_F(RBCCoreTest, DeliverAfterReadyAndEnoughStripes)
{
    auto core = create_core();

    const auto root = make_hash(3);
    collect_effects(core.handle_message(make_val(leader, root, 0x01)));
    collect_effects(core.handle_message(make_echo(2, root, 0x02)));
    collect_effects(core.handle_message(make_echo(3, root, 0x03)));

    const auto ready2_effects = collect_effects(core.handle_message(make_ready(2, root)));
    EXPECT_TRUE(ready2_effects.empty());

    const auto ready3_effects = collect_effects(core.handle_message(make_ready(3, root)));
    ASSERT_EQ(ready3_effects.size(), 1U);
    EXPECT_EQ(ready3_effects.front().type, Effect::Type::Deliver);
    ASSERT_TRUE(ready3_effects.front().root_hash.has_value());
    EXPECT_EQ(*ready3_effects.front().root_hash, root);
}

TEST_F(RBCCoreTest, ReadyAmplificationAfterFPlusOneReady)
{
    auto core = create_core();

    const auto root = make_hash(4);

    const auto ready2_effects = collect_effects(core.handle_message(make_ready(2, root)));
    EXPECT_TRUE(ready2_effects.empty());

    const auto ready3_effects = collect_effects(core.handle_message(make_ready(3, root)));
    ASSERT_EQ(ready3_effects.size(), 1U);
    EXPECT_EQ(ready3_effects.front().type, Effect::Type::Broadcast);
    ASSERT_TRUE(ready3_effects.front().msg.has_value());
    EXPECT_TRUE(std::holds_alternative<ReadyPayload>(ready3_effects.front().msg->payload));

    const auto ready0_effects = collect_effects(core.handle_message(make_ready(0, root)));
    EXPECT_TRUE(ready0_effects.empty());
}

} // namespace Honey::BFT::RBC
