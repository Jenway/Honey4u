#include "core/coin/coin_core.hpp"
#include <cstring>

namespace Honey::BFT::Coin {

Core::Core(const CoinConfig& config)
    : sid_(config.session_id)
    , pid_(config.node_id)
    , N_(config.total_nodes)
    , f_(config.fault_tolerance)
{
}

std::generator<Action> Core::request_coin(int round, const SignatureShare& my_share)
{
    // Only broadcast if not already requested
    if (!requested_.contains(round)) {
        requested_.insert(round);

        // Add own share locally
        received_[round][pid_] = my_share;

        // Broadcast share
        co_yield Action {
            .type = Action::Type::BroadcastShare,
            .round = round,
            .my_share = my_share
        };

        // Check if we can combine immediately (unlikely but possible)
        for (auto action : try_combine(round)) {
            co_yield action;
        }
    }
}

std::generator<Action> Core::on_share(int round, int sender, const SignatureShare& share)
{
    // Ignore if round is finished
    if (finished_.contains(round))
        co_return;

    // Ignore duplicate shares from same sender
    if (received_[round].contains(sender))
        co_return;

    // Add share
    received_[round][sender] = share;

    // Try to combine if threshold met
    for (auto action : try_combine(round)) {
        co_yield action;
    }
}

void Core::mark_finished(int round, uint8_t bit)
{
    finished_.insert(round);
    outputs_[round] = bit;
}

std::vector<std::byte> Core::make_payload_bytes(int round) const
{
    std::vector<std::byte> payload(sizeof(int) * 2);
    std::memcpy(payload.data(), &sid_, sizeof(int));
    std::memcpy(payload.data() + sizeof(int), &round, sizeof(int));
    return payload;
}

std::generator<Action> Core::try_combine(int round)
{
    // Already finished
    if (finished_.contains(round))
        co_return;

    // Check if threshold met
    if (received_[round].size() < static_cast<size_t>(f_ + 1))
        co_return;

    // Already tried to combine
    if (combination_triggered_[round])
        co_return;

    combination_triggered_[round] = true;

    // Collect shares for combining
    std::vector<PartialSignature> shares;
    shares.reserve(received_[round].size());
    for (const auto& [sender, share] : received_[round]) {
        shares.push_back(PartialSignature { .player_id = sender, .value = share });
    }

    // Yield combine action
    co_yield Action {
        .type = Action::Type::CombineSignatures,
        .round = round,
        .shares_to_combine = std::span(shares)
    };
}

} // namespace Honey::BFT::Coin
