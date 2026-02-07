#pragma once

#include "core/mvba/messages.hpp"
#include <generator>
#include <map>
#include <optional>
#include <set>
#include <vector>

namespace Honey::BFT::MVBA {

class Core {
public:
    explicit Core(const MVBAConfig& config);

    // Input: My proposal to start my PRBC instance
    std::generator<Action> start(Proposal proposal);

    // Input: Message from network
    std::generator<Action> on_msg(MVBAMessage msg);

    // Input: PRBC result (from Service, for a specific instance)
    // The Service runs PRBCs. When PRBC[i] outputs, it calls this.
    // Core updates state and might trigger Election.
    // Wait, Core is pure. It shouldn't run PRBCs?
    // ARCHITECTURE DECISION:
    // Option A: MVBACore manages N PRBCCore instances internally.
    // Option B: MVBAService manages N PRBCServices, MVBACore only coordinates results.
    //
    // Given PRBCCore is pure, MVBACore CAN manage N PRBCCores.
    // This is cleaner: One "on_msg" for MVBA routes to specific PRBCCore.
    // The "Action" from PRBC is wrapped/transformed into MVBA Action.
    // This keeps the "Core is Pure" philosophy intact.

    // Input: Coin/Election result
    // If we use an external coin, we need an input for it.
    std::generator<Action> on_coin_result(int leader_id);

    std::generator<Action> on_prbc_result(int instance_id, PrbcResult result);

private:
    MVBAConfig config_;

    // Track finished PRBCs
    std::set<int> finished_prbcs_;
    std::map<int, PrbcResult> prbc_results_;
    bool election_started_ = false;
    bool output_produced_ = false;
    std::optional<int> elected_leader_;

    // Helpers
    std::generator<Action> check_election_start();
    std::generator<Action> try_output();
};

} // namespace Honey::BFT::MVBA
