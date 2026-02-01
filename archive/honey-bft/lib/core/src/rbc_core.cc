#include "core/rbc/rbc_core.hpp"
#include <variant>

namespace Honey::BFT::RBC {

Core::Core(const RBCConfig& config)
    : sid_(config.session_id)
    , pid_(config.node_id)
    , N_(config.total_nodes)
    , f_(config.fault_tolerance)
    , leader_(config.leader_id)
{
}

std::generator<Action> Core::on_msg(RBCMessage msg)
{
    if (std::holds_alternative<ValPayload>(msg.payload)) {
        if (msg.type == RBCMessage::Type::Leader) {
            for (auto action : start_as_leader(std::get<ValPayload>(msg.payload))) {
                co_yield action;
            }
        } else {
            for (auto action : on_val(msg.sender, std::get<ValPayload>(msg.payload))) {
                co_yield action;
            }
        }
    } else if (std::holds_alternative<EchoPayload>(msg.payload)) {
        for (auto action : on_echo(msg.sender, std::get<EchoPayload>(msg.payload))) {
            co_yield action;
        }
    } else if (std::holds_alternative<ReadyPayload>(msg.payload)) {
        for (auto action : on_ready(msg.sender, std::get<ReadyPayload>(msg.payload))) {
            co_yield action;
        }
    }
}

std::generator<Action> Core::start_as_leader(ValPayload self_val)
{
    if (pid_ != leader_)
        co_return;

    current_root_ = self_val.root_hash;

    stripes_[self_val.root_hash][pid_] = self_val.stripe;

    for (auto action : co_yield_actions(self_val.root_hash)) {
        co_yield action;
    }
}

std::generator<Action> Core::on_val(int sender, ValPayload p)
{
    if (!is_valid_val(sender, p))
        co_return;

    if (!current_root_)
        current_root_ = p.root_hash;

    stripes_[p.root_hash][sender] = p.stripe;

    for (auto action : co_yield_actions(p.root_hash)) {
        co_yield action;
    }
}

std::generator<Action> Core::on_echo(int sender, EchoPayload p)
{
    if (!accept_root(p.root_hash))
        co_return;
    if (echo_senders_[p.root_hash].contains(sender))
        co_return;

    echo_senders_[p.root_hash].insert(sender);
    stripes_[p.root_hash][sender] = p.stripe;

    for (auto action : co_yield_actions(p.root_hash)) {
        co_yield action;
    }
}

std::generator<Action> Core::on_ready(int sender, ReadyPayload p)
{
    if (!accept_root(p.root_hash))
        co_return;
    if (ready_senders_[p.root_hash].contains(sender))
        co_return;

    ready_senders_[p.root_hash].insert(sender);

    for (auto action : co_yield_actions(p.root_hash)) {
        co_yield action;
    }
}

std::generator<Action> Core::co_yield_actions(Hash root)
{
    if (should_send_ready(root) && !ready_sent_for_[root]) {
        ready_sent_for_[root] = true;
        co_yield Action {
            .type = Action::Type::BroadcastReady,
            .root_hash = root
        };
    }

    if (can_decode(root) && !decode_triggered_for_[root]) {
        decode_triggered_for_[root] = true;

        std::vector<std::pair<int, std::span<const std::byte>>> shards;
        for (const auto& [node, stripe] : stripes_[root]) {
            shards.emplace_back(node, std::span<const std::byte>(stripe));
        }

        co_yield Action {
            .type = Action::Type::Decode,
            .root_hash = root,
            .shards = std::span(shards)
        };
    }
}

bool Core::accept_root(const Hash& h) const
{
    return !current_root_ || *current_root_ == h;
}

bool Core::is_valid_val(int sender, const ValPayload& p) const
{
    if (sender != leader_)
        return false;
    if (current_root_ && *current_root_ != p.root_hash)
        return false;
    return true;
}

bool Core::should_send_ready(const Hash& root) const
{
    return count_echo(root) >= N_ - f_
        || count_ready(root) >= f_ + 1;
}

bool Core::can_decode(const Hash& root) const
{
    return count_ready(root) >= ((2 * f_) + 1)
        && stripes_.at(root).size() >= static_cast<size_t>(N_ - (2 * f_));
}

size_t Core::count_echo(const Hash& root) const
{
    auto it = echo_senders_.find(root);
    return it == echo_senders_.end() ? 0 : it->second.size();
}

size_t Core::count_ready(const Hash& root) const
{
    auto it = ready_senders_.find(root);
    return it == ready_senders_.end() ? 0 : it->second.size();
}

} // namespace Honey::BFT::RBC
