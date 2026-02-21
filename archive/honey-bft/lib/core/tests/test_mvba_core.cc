#include "core/mvba/mvba_core.hpp"
#include <doctest/doctest.h>

namespace Honey::BFT::MVBA {

TEST_CASE("MVBACoreTest.StartsElectionAfterThreshold")
{
    MVBAConfig cfg { .session_id = 1, .node_id = 0, .total_nodes = 4, .fault_tolerance = 1 };
    Core core(cfg);

    // Start PRBC for self
    Proposal proposal { .data = { std::byte { 0x01 } } };
    bool started_prbc = false;
    for (auto action : core.start(proposal)) {
        if (action.type == Action::Type::StartPrbc) {
            started_prbc = true;
        }
    }
    CHECK(started_prbc);

    // Finish 3 PRBCs (N-f)
    bool started_ba = false;
    for (int i = 0; i < 3; ++i) {
        PrbcResult res { .data = { std::byte { 0x10 } }, .proof = { std::byte { 0xAA } } };
        for (auto action : core.on_prbc_result(i, res)) {
            if (action.type == Action::Type::StartBa) {
                started_ba = true;
                CHECK_EQ(action.ba_input, 1);
            }
        }
    }
    CHECK(started_ba);
}

TEST_CASE("MVBACoreTest.OutputsWhenLeaderFinished")
{
    MVBAConfig cfg { .session_id = 1, .node_id = 0, .total_nodes = 4, .fault_tolerance = 1 };
    Core core(cfg);

    // Finish PRBC for leader 2
    PrbcResult res { .data = { std::byte { 0x42 } }, .proof = { std::byte { 0xBB } } };
    bool got_output = false;
    // Coin selects leader 2 (before PRBC result)
    for (auto action : core.on_coin_result(2)) {
        (void)action;
    }

    // Now finish PRBC for leader 2
    Output out;
    for (auto action : core.on_prbc_result(2, res)) {
        if (action.type == Action::Type::Output) {
            out = action.output;
            got_output = true;
        }
    }

    CHECK(got_output);
    CHECK_EQ(out.leader_id, 2);
    CHECK_EQ(out.data, std::vector<std::byte>({ std::byte { 0x42 } }));
    CHECK_EQ(out.proof, std::vector<std::byte>({ std::byte { 0xBB } }));
}

} // namespace Honey::BFT::MVBA
