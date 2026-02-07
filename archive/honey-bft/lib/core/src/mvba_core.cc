#include "core/mvba/mvba_core.hpp"

namespace Honey::BFT::MVBA {

Core::Core(const MVBAConfig& config)
    : config_(config)
{
}

std::generator<Action> Core::start(Proposal proposal)
{
    co_yield Action {
        .type = Action::Type::StartPrbc,
        .instance_id = config_.node_id,
        .prbc_input = std::move(proposal.data)
    };
}

std::generator<Action> Core::on_prbc_result(int instance_id, PrbcResult result)
{
    if (finished_prbcs_.contains(instance_id))
        co_return;

    finished_prbcs_.insert(instance_id);
    prbc_results_[instance_id] = std::move(result);

    for (auto action : check_election_start())
        co_yield action;
    for (auto action : try_output())
        co_yield action;
}

std::generator<Action> Core::on_msg(MVBAMessage /*msg*/)
{
    // MVBA Core does not process network messages directly in this design.
    // The service routes PRBC/BA messages to their respective components.
    co_return;
}

std::generator<Action> Core::on_coin_result(int leader_id)
{
    if (output_produced_)
        co_return;

    elected_leader_ = leader_id;

    for (auto action : try_output())
        co_yield action;
}

std::generator<Action> Core::check_election_start()
{
    if (election_started_)
        co_return;

    if (finished_prbcs_.size() >= static_cast<size_t>(config_.total_nodes - config_.fault_tolerance)) {
        election_started_ = true;
        co_yield Action {
            .type = Action::Type::StartBa,
            .ba_round = 0,
            .ba_input = 1
        };
    }
}

std::generator<Action> Core::try_output()
{
    if (output_produced_ || !elected_leader_)
        co_return;

    int leader_id = *elected_leader_;
    auto it = prbc_results_.find(leader_id);
    if (it == prbc_results_.end())
        co_return;

    output_produced_ = true;
    co_yield Action {
        .type = Action::Type::Output,
        .output = Output { .leader_id = leader_id, .data = it->second.data, .proof = it->second.proof }
    };
}

} // namespace Honey::BFT::MVBA
