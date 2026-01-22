#include "core/coin/coin_core.hpp"
#include <span>
#include <string>

namespace Honey::BFT::Coin {

Core::Core(int sid, int pid, int N, int f)
    : sid_(sid)
    , pid_(pid)
    , N_(N)
    , f_(f)
{
}

bool Core::has_requested(int round) const
{
    return requested_.contains(round);
}

void Core::mark_requested(int round)
{
    requested_.insert(round);
}

bool Core::add_share(int round, int sender, const SignatureShare& share)
{
    if (received_[round].contains(sender)) {
        return false;
    }

    received_[round][sender] = share;

    return is_threshold_met(round);
}

bool Core::is_threshold_met(int round) const
{
    if (!received_.contains(round)) {
        return false;
    }
    return static_cast<int>(received_.at(round).size()) >= threshold();
}

std::vector<PartialSignature> Core::get_shares(int round) const
{
    std::vector<PartialSignature> result;

    if (!received_.contains(round)) {
        return result;
    }

    const auto& shares_map = received_.at(round);
    result.reserve(shares_map.size());

    for (const auto& [sender, share] : shares_map) {
        result.push_back({
            .player_id = sender,
            .value = share,
        });
    }

    return result;
}

bool Core::is_finished(int round) const
{
    return finished_.contains(round);
}

void Core::mark_finished(int round)
{
    finished_.insert(round);
    // Clean up memory for finished round
    received_.erase(round);
}

std::vector<std::byte> Core::make_payload_bytes(int round) const
{
    // Build payload: H(sid, round) input
    std::string msg = std::to_string(sid_) + ":" + std::to_string(round);
    auto span = std::as_bytes(std::span(msg));
    return { span.begin(), span.end() };
}

} // namespace Honey::BFT::Coin
