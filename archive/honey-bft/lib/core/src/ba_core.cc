#include "core/ba/ba_core.hpp"

namespace Honey::BFT::BA {

Core::Core(const BACoreConfig& config)
    : N_(config.total_nodes)
    , f_(config.fault_tolerance)
    , my_pid_(config.node_id)
    , sid_(config.session_id)
{
}

std::generator<Action> Core::start_round(int r, int estimate)
{
    ensure_round(r);
    rounds_[r].estimate = estimate;
    current_r_ = r;

    // Broadcast initial BVAL
    rounds_[r].bval_sent.insert(estimate);
    co_yield Action {
        .type = Action::Type::BroadcastBval,
        .round = r,
        .value = estimate
    };
}

std::generator<Action> Core::on_bval(int r, NodeId sender, int val)
{
    if (val != 0 && val != 1)
        co_return;

    ensure_round(r);
    auto& rs = rounds_[r];

    // Ignore duplicates
    if (rs.bval_senders[val].contains(sender))
        co_return;

    rs.bval_senders[val].insert(sender);

    // Update bin_values when receiving 2f+1 BVALs
    if (rs.bval_senders[val].size() >= static_cast<size_t>((2 * f_) + 1)) {
        rs.bin_values.insert(val);
    }

    // Broadcast BVAL if received f+1 and not sent yet
    if (rs.bval_senders[val].size() >= static_cast<size_t>(f_ + 1)
        && !rs.bval_sent.contains(val)) {
        rs.bval_sent.insert(val);
        co_yield Action {
            .type = Action::Type::BroadcastBval,
            .round = r,
            .value = val
        };
    }

    // Check if should send AUX
    if (!rs.aux_sent && !rs.bin_values.empty()) {
        rs.aux_sent = true;
        int w = *rs.bin_values.begin();
        co_yield Action {
            .type = Action::Type::BroadcastAux,
            .round = r,
            .value = w
        };
    }
}

std::generator<Action> Core::on_aux(int r, NodeId sender, int val)
{
    if (val != 0 && val != 1)
        co_return;

    ensure_round(r);
    auto& rs = rounds_[r];

    // Store AUX message
    rs.aux_msgs[sender] = val;

    // Check if ready for coin
    if (!rs.coin_requested && is_ready_for_coin(r)) {
        rs.coin_requested = true;
        co_yield Action {
            .type = Action::Type::RequestCoin,
            .round = r
        };
    }
}

std::generator<Action> Core::on_coin_result(int r, int coin_value)
{
    ensure_round(r);
    auto& rs = rounds_[r];

    // Calculate vals: all valid AUX values
    std::set<int> vals;
    for (const auto& [sender, val] : rs.aux_msgs) {
        if (rs.bin_values.contains(val)) {
            vals.insert(val);
        }
    }

    if (vals.empty())
        co_return;

    int next_estimate;
    bool should_output = false;

    if (vals.size() == 1) {
        int b = *vals.begin();
        next_estimate = b;
        // Output if b matches coin
        if (b == coin_value && !decided_) {
            decided_ = true;
            should_output = true;
            co_yield Action {
                .type = Action::Type::Output,
                .round = r,
                .value = b,
                .decided = true
            };
        }
    } else {
        // Multiple values, use coin as next estimate
        next_estimate = coin_value;
    }

    // If not decided, start next round
    if (!decided_) {
        for (auto action : start_round(r + 1, next_estimate)) {
            co_yield action;
        }
    }
}

void Core::ensure_round(int r)
{
    if (!rounds_.contains(r)) {
        rounds_[r] = RoundState {};
    }
}

bool Core::is_ready_for_coin(int r) const
{
    const auto& rs = rounds_.at(r);

    // Need at least N-f AUX messages
    if (rs.aux_msgs.size() < static_cast<size_t>(N_ - f_))
        return false;

    // Count valid AUX (values in bin_values)
    int valid_aux_count = 0;
    for (const auto& [sender, val] : rs.aux_msgs) {
        if (rs.bin_values.contains(val)) {
            valid_aux_count++;
        }
    }

    return valid_aux_count >= (N_ - f_);
}

} // namespace Honey::BFT::BA
