#include "core/coin/coin_core.hpp"
#include "core/coin/messages.hpp"
#include <doctest/doctest.h>

#include <algorithm>

#include <vector>

namespace Honey::BFT::Coin {

struct CoinCoreTest {
    static constexpr int N = 4;
    static constexpr int f = 1;
    static constexpr int MyPid = 1;
    static constexpr int Sid = 200;

    CoinConfig config {
        .session_id = Sid,
        .node_id = MyPid,
        .total_nodes = N,
        .fault_tolerance = f
    };

    SignatureShare make_share(uint64_t val)
    {
        SignatureShare sig;
        std::ranges::fill(sig, 0);
        sig[0] = val;
        return sig;
    }

    PartialSignature make_partial(int player_id, uint64_t val)
    {
        return PartialSignature {
            .player_id = player_id,
            .value = make_share(val)
        };
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

TEST_CASE_FIXTURE(CoinCoreTest, "CoinCoreTest.RequestCoinBroadcastsShare")
{
    Core core(config);
    auto my_share = make_share(0xAA);

    auto actions = collect_actions(core.request_coin(1, my_share));

    REQUIRE_EQ(actions.size(), 1);
    CHECK_EQ(actions[0].type, Action::Type::BroadcastShare);
    CHECK_EQ(actions[0].round, 1);
    CHECK_EQ(actions[0].my_share, my_share);
}

TEST_CASE_FIXTURE(CoinCoreTest, "CoinCoreTest.CollectingSharesTriggersOutput")
{
    Core core(config);
    auto my_share = make_share(0xAA);

    // Request coin first
    collect_actions(core.request_coin(1, my_share));

    // Collect threshold shares (f+1 = 2 out of 4)
    // We count our own share + 1 other, or 2 others
    auto actions1 = collect_actions(core.on_share(1, 0, make_share(0x00)));
    auto actions2 = collect_actions(core.on_share(1, 2, make_share(0x11)));

    // Now we have: our share + 2 from others = 3 total >= f+1 = 2
    // One of these should trigger combine
    std::vector<Action> all_actions = actions1;
    all_actions.insert(all_actions.end(), actions2.begin(), actions2.end());

    bool found_combine = false;
    for (const auto& action : all_actions) {
        if (action.type == Action::Type::CombineSignatures) {
            found_combine = true;
            break;
        }
    }
    CHECK(found_combine);
}

TEST_CASE_FIXTURE(CoinCoreTest, "CoinCoreTest.DuplicateSharesIgnored")
{
    Core core(config);
    auto my_share = make_share(0xAA);

    collect_actions(core.request_coin(1, my_share));

    // Send same share twice from player 0
    auto first_actions = collect_actions(core.on_share(1, 0, make_share(0x00)));
    auto second_actions = collect_actions(core.on_share(1, 0, make_share(0x00)));

    // Second one should not produce additional actions
    CHECK_EQ(second_actions.size(), 0);
}

TEST_CASE_FIXTURE(CoinCoreTest, "CoinCoreTest.MultipleRoundsIndependent")
{
    Core core(config);

    // Request coin for round 1
    auto share1 = make_share(0xAA);
    collect_actions(core.request_coin(1, share1));

    // Request coin for round 2
    auto share2 = make_share(0xBB);
    auto actions = collect_actions(core.request_coin(2, share2));

    REQUIRE_EQ(actions.size(), 1);
    CHECK_EQ(actions[0].round, 2);
    CHECK_EQ(actions[0].my_share, share2);
}

TEST_CASE_FIXTURE(CoinCoreTest, "CoinCoreTest.SharesForWrongRoundIgnored")
{
    Core core(config);
    auto my_share = make_share(0xAA);

    collect_actions(core.request_coin(1, my_share));

    // Send share for round 2 when we only requested round 1
    auto actions = collect_actions(core.on_share(2, 0, make_share(0x00)));

    // Should not produce any actions
    CHECK_EQ(actions.size(), 0);
}

} // namespace Honey::BFT::Coin
