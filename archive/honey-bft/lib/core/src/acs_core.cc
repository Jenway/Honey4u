#include "core/acs/acs_core.hpp"

namespace Honey::BFT::ACS {

Core::Core(const ACSConfig& config)
    : sid_(config.session_id)
    , pid_(config.node_id)
    , N_(config.total_nodes)
    , f_(config.fault_tolerance)
{
}

std::generator<Action> Core::on_rbc_complete(int index, std::vector<Byte> data)
{
    if (rbc_completed_.contains(index))
        co_return;

    rbc_completed_.insert(index);
    rbc_data_[index] = std::move(data);

    // If haven't proposed to this BA yet, propose 1
    if (!ba_input_decided_.contains(index)) {
        ba_input_decided_[index] = 1;
        co_yield Action {
            .type = Action::Type::ProposeToBa,
            .ba_index = index,
            .ba_value = 1
        };
    }
}

std::generator<Action> Core::on_ba_complete(int index, int decision)
{
    if (ba_completed_.contains(index))
        co_return;

    ba_completed_.insert(index);
    ba_decisions_[index] = decision;

    if (decision == 1) {
        ba_yes_count_++;
    }

    // Check if we've reached N-f BA instances with decision 1
    if (ba_yes_count_ >= (N_ - f_) && !vote_0_triggered_) {
        vote_0_triggered_ = true;

        // Propose 0 to all BA instances that haven't received input yet
        for (int i = 0; i < N_; ++i) {
            if (!ba_input_decided_.contains(i)) {
                ba_input_decided_[i] = 0;
                co_yield Action {
                    .type = Action::Type::ProposeToBa,
                    .ba_index = i,
                    .ba_value = 0
                };
            }
        }
    }

    // Check if all BA instances have completed
    if (static_cast<int>(ba_completed_.size()) == N_ && !output_triggered_) {
        output_triggered_ = true;

        // Collect output: RBC values where BA decided 1
        output_.clear();
        for (const auto& [idx, dec] : ba_decisions_) {
            if (dec == 1 && rbc_data_.contains(idx)) {
                output_.push_back(rbc_data_.at(idx));
            }
        }

        co_yield Action {
            .type = Action::Type::Output,
            .output_data = std::span(output_)
        };
    }
}

} // namespace Honey::BFT::ACS
