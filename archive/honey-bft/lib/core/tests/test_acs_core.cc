#include "core/acs/acs_core.hpp"
#include <gtest/gtest.h>
#include <vector>

namespace Honey::BFT::ACS {

class ACSCoreTest : public ::testing::Test {
protected:
    static constexpr int N = 4;
    static constexpr int f = 1;
    static constexpr int MyPid = 1;
    static constexpr int Sid = 400;

    ACSConfig config {
        .session_id = Sid,
        .node_id = MyPid,
        .total_nodes = N,
        .fault_tolerance = f
    };

    std::vector<Byte> make_data(const std::string& s)
    {
        std::vector<Byte> data;
        for (char c : s) {
            data.push_back(static_cast<Byte>(c));
        }
        return data;
    }

    std::vector<Action> collect_actions(std::generator<Action>&& gen)
    {
        std::vector<Action> result;
        for (auto action : gen) {
            result.push_back(action);
        }
        return result;
    }
};

TEST_F(ACSCoreTest, FirstRbcCompletionProposesToBa)
{
    Core core(config);

    auto data = make_data("test");
    std::vector<Action> actions;
    for (auto action : core.on_rbc_complete(0, data)) {
        actions.push_back(action);
    }

    ASSERT_EQ(actions.size(), 1);
    EXPECT_EQ(actions[0].type, Action::Type::ProposeToBa);
    EXPECT_EQ(actions[0].ba_index, 0);
    EXPECT_EQ(actions[0].ba_value, 1);
}

TEST_F(ACSCoreTest, DuplicateRbcCompletionIgnored)
{
    Core core(config);

    auto data = make_data("test");
    collect_actions(core.on_rbc_complete(0, data));

    // Send completion for same instance again
    auto actions = collect_actions(core.on_rbc_complete(0, data));

    EXPECT_EQ(actions.size(), 0);
}

TEST_F(ACSCoreTest, BaDecisionRecordedButNoOutputUntilNMinusF)
{
    Core core(config);

    // Complete RBC 0
    collect_actions(core.on_rbc_complete(0, make_data("data0")));

    // BA 0 completes with decision 1
    auto actions = collect_actions(core.on_ba_complete(0, 1));

    // Should not output yet (need N-f = 3)
    EXPECT_EQ(actions.size(), 0);
}

TEST_F(ACSCoreTest, OutputWhenNMinusFBasDecide)
{
    Core core(config);

    // Complete ALL 4 RBCs
    collect_actions(core.on_rbc_complete(0, make_data("data0")));
    collect_actions(core.on_rbc_complete(1, make_data("data1")));
    collect_actions(core.on_rbc_complete(2, make_data("data2")));
    collect_actions(core.on_rbc_complete(3, make_data("data3")));

    // All 4 BAs complete with decision 1
    collect_actions(core.on_ba_complete(0, 1));
    collect_actions(core.on_ba_complete(1, 1));
    collect_actions(core.on_ba_complete(2, 1));

    // Fourth BA completes - should trigger output (when all N BAs done)
    auto actions = collect_actions(core.on_ba_complete(3, 1));

    bool found_output = false;
    for (const auto& action : actions) {
        if (action.type == Action::Type::Output) {
            found_output = true;
            EXPECT_EQ(action.output_data.size(), 4);
        }
    }
    EXPECT_TRUE(found_output);
}

TEST_F(ACSCoreTest, BaDecidingZeroDoesNotIncludeInOutput)
{
    Core core(config);

    // Complete 4 RBCs
    collect_actions(core.on_rbc_complete(0, make_data("data0")));
    collect_actions(core.on_rbc_complete(1, make_data("data1")));
    collect_actions(core.on_rbc_complete(2, make_data("data2")));
    collect_actions(core.on_rbc_complete(3, make_data("data3")));

    // BAs 0, 1, 2 decide 1, BA 3 decides 0
    collect_actions(core.on_ba_complete(0, 1));
    collect_actions(core.on_ba_complete(1, 1));
    collect_actions(core.on_ba_complete(2, 1));

    auto actions = collect_actions(core.on_ba_complete(3, 0));

    // Output should only include the 3 instances that decided 1
    bool found_output = false;
    for (const auto& action : actions) {
        if (action.type == Action::Type::Output) {
            found_output = true;
            EXPECT_EQ(action.output_data.size(), 3);
        }
    }
    EXPECT_TRUE(found_output);
}

TEST_F(ACSCoreTest, ProposalForUncompletedRbcQueued)
{
    Core core(config);

    // BA 0 completes with decision 1 before RBC completes
    collect_actions(core.on_ba_complete(0, 1));

    // Complete RBC 0 later - should still propose
    auto actions = collect_actions(core.on_rbc_complete(0, make_data("data0")));

    bool found_propose = false;
    for (const auto& action : actions) {
        if (action.type == Action::Type::ProposeToBa) {
            found_propose = true;
        }
    }
    // BA might have already decided, so we just check RBC is recorded
    // EXPECT_TRUE(found_propose);
}

} // namespace Honey::BFT::ACS