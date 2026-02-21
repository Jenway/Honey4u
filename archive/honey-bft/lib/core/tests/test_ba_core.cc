#include "core/ba/ba_core.hpp"
#include "core/ba/messages.hpp"
#include <doctest/doctest.h>
#include <vector>

namespace Honey::BFT::BA {

struct BACoreTest {
    static constexpr int N = 4;
    static constexpr int f = 1;
    static constexpr int MyPid = 1;
    static constexpr int Sid = 300;

    BACoreConfig config {
        .session_id = Sid,
        .node_id = MyPid,
        .total_nodes = N,
        .fault_tolerance = f
    };

    std::vector<Action> collect_actions(std::generator<Action>&& gen)
    {
        std::vector<Action> result;
        for (auto action : gen) {
            result.push_back(action);
        }
        return result;
    }
};

TEST_CASE_FIXTURE(BACoreTest, "BACoreTest.ProposeValueBroadcastsBval")
{
    Core core(config);

    auto actions = collect_actions(core.start_round(0, 1));

    REQUIRE_GE(actions.size(), 1);
    bool found_bval = false;
    for (const auto& action : actions) {
        if (action.type == Action::Type::BroadcastBval) {
            found_bval = true;
            CHECK_EQ(action.round, 0);
            CHECK_EQ(action.value, 1);
        }
    }
    CHECK(found_bval);
}

TEST_CASE_FIXTURE(BACoreTest, "BACoreTest.BvalQuorumTriggersBinValue")
{
    Core core(config);

    // Start with value 1
    collect_actions(core.start_round(0, 1));

    // Receive N-f Bval(1) messages (3 including myself)
    collect_actions(core.on_bval(0, 0, 1));
    collect_actions(core.on_bval(0, 2, 1));
    auto actions = collect_actions(core.on_bval(0, 3, 1));

    // Should broadcast Aux with bin_values
    bool found_aux = false;
    for (const auto& action : actions) {
        if (action.type == Action::Type::BroadcastAux) {
            found_aux = true;
            CHECK_EQ(action.round, 0);
        }
    }
    CHECK(found_aux);
}

TEST_CASE_FIXTURE(BACoreTest, "BACoreTest.AuxQuorumRequestsCoin")
{
    Core core(config);

    collect_actions(core.start_round(0, 1));

    // Get to Aux phase
    collect_actions(core.on_bval(0, 0, 1));
    collect_actions(core.on_bval(0, 2, 1));
    collect_actions(core.on_bval(0, 3, 1));

    // Receive N-f Aux messages
    collect_actions(core.on_aux(0, 0, 1));
    collect_actions(core.on_aux(0, 2, 1));
    auto actions = collect_actions(core.on_aux(0, 3, 1));

    // Should request coin
    bool found_coin_request = false;
    for (const auto& action : actions) {
        if (action.type == Action::Type::RequestCoin) {
            found_coin_request = true;
            CHECK_EQ(action.round, 0);
        }
    }
    CHECK(found_coin_request);
}

TEST_CASE_FIXTURE(BACoreTest, "BACoreTest.CoinResultTriggersDecision")
{
    Core core(config);

    // Setup: go through full round with value 1
    collect_actions(core.start_round(0, 1));
    collect_actions(core.on_bval(0, 0, 1));
    collect_actions(core.on_bval(0, 2, 1));
    collect_actions(core.on_bval(0, 3, 1));
    collect_actions(core.on_aux(0, 0, 1));
    collect_actions(core.on_aux(0, 2, 1));
    collect_actions(core.on_aux(0, 3, 1));

    // Coin returns 1 (matching our value)
    auto actions = collect_actions(core.on_coin_result(0, 1));

    // Should output decision
    bool found_output = false;
    for (const auto& action : actions) {
        if (action.type == Action::Type::Output) {
            found_output = true;
            CHECK_EQ(action.value, 1);
            CHECK(action.decided);
        }
    }
    CHECK(found_output);
}

TEST_CASE_FIXTURE(BACoreTest, "BACoreTest.DuplicateMessagesIgnored")
{
    Core core(config);

    collect_actions(core.start_round(0, 1));

    // Send Bval from same sender twice
    auto first_actions = collect_actions(core.on_bval(0, 2, 1));
    auto second_actions = collect_actions(core.on_bval(0, 2, 1));

    // No new actions from duplicate
    CHECK_EQ(second_actions.size(), 0);
}

} // namespace Honey::BFT::BA
