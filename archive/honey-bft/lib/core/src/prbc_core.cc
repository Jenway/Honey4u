#include "core/prbc/prbc_core.hpp"
#include <variant>

namespace Honey::BFT::PRBC {

using Honey::BFT::RBC::RBCMessage; // Use types for casting/serialization helpers if needed

Core::Core(const RBCConfig& config)
    : sid_(config.session_id)
    , pid_(config.node_id)
    , N_(config.total_nodes)
    , f_(config.fault_tolerance)
    , leader_(config.leader_id)
{
}

std::vector<std::pair<int, std::vector<std::byte>>> Core::get_shards(const Hash& root) const
{
    std::vector<std::pair<int, std::vector<std::byte>>> shards;
    auto it = stripes_.find(root);
    if (it != stripes_.end()) {
        for (const auto& [node, stripe] : it->second) {
            shards.emplace_back(node, stripe);
        }
    }
    return shards;
}

std::vector<std::pair<int, std::vector<std::byte>>> Core::get_signature_shares(const Hash& root) const
{
    std::vector<std::pair<int, std::vector<std::byte>>> shares;
    auto it = signature_shares_.find(root);
    if (it != signature_shares_.end()) {
        for (const auto& [node, share] : it->second) {
            shares.emplace_back(node, share);
        }
    }
    return shares;
}

std::generator<Action> Core::on_msg(PRBCMessage msg)
{
    if (std::holds_alternative<ValPayload>(msg.payload)) {
        if (msg.type == PRBCMessage::Type::Leader) {
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
        // Note: For PRBC, Ready messages contain signatures.
        // We process the basic Ready logic here (counting), but the Signature
        // MUST be verified by the Service before calling on_signature_share.
        // The Service should call on_msg -> checks structure/logic -> returns no actions usually
        // Then Service verifies sig -> calls on_signature_share -> returns actions (maybe Output).
        // BUT, we need to count Ready for amplification threshold (f+1).
        // Since we can't verify sig here, we assume Service verified it BEFORE calling on_msg?
        // Or we rely on on_signature_share to handle EVERYTHING about Ready?
        // Let's assume on_msg handles the flow, but on_signature_share handles the specific sigma.

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

    if (!echo_sent_for_[self_val.root_hash]) {
        echo_sent_for_[self_val.root_hash] = true;
        echo_senders_[self_val.root_hash].insert(pid_);

        // Serialize Echo
        EchoPayload echo_p {
            .root_hash = self_val.root_hash,
            .proof_index = self_val.proof_index,
            .merkle_path = self_val.merkle_path,
            .stripe = self_val.stripe
        };
        std::vector<std::byte> payload;
        payload.push_back(static_cast<std::byte>(PRBCMessage::Type::Echo));

        co_yield Action { .type = Action::Type::Broadcast, .payload = std::move(payload) };
    }

    // Check if we can proceed (unlikely this early, but consistent with RBC)
    for (auto action : try_send_ready(self_val.root_hash))
        co_yield action;
}

std::generator<Action> Core::on_val(int sender, ValPayload p)
{
    if (!is_valid_val(sender, p))
        co_return;

    if (!current_root_)
        current_root_ = p.root_hash;

    stripes_[p.root_hash][sender] = p.stripe;

    if (!echo_sent_for_[p.root_hash]) {
        echo_sent_for_[p.root_hash] = true;
        echo_senders_[p.root_hash].insert(pid_);

        EchoPayload echo_p {
            .root_hash = p.root_hash,
            .proof_index = p.proof_index,
            .merkle_path = p.merkle_path,
            .stripe = p.stripe
        };
        std::vector<std::byte> payload;
        payload.push_back(static_cast<std::byte>(PRBCMessage::Type::Echo));

        co_yield Action { .type = Action::Type::Broadcast, .payload = std::move(payload) };
    }

    for (auto action : try_send_ready(p.root_hash))
        co_yield action;
}

std::generator<Action> Core::on_echo(int sender, EchoPayload p)
{
    if (!accept_root(p.root_hash))
        co_return;
    if (echo_senders_[p.root_hash].contains(sender))
        co_return;

    echo_senders_[p.root_hash].insert(sender);
    stripes_[p.root_hash][sender] = p.stripe;

    for (auto action : try_send_ready(p.root_hash))
        co_yield action;

    // Check completion in case we have enough signatures but were missing shards
    for (auto action : check_completion(p.root_hash))
        co_yield action;
}

std::generator<Action> Core::on_ready(int sender, ReadyPayload p)
{
    if (!accept_root(p.root_hash))
        co_return;
    if (ready_senders_[p.root_hash].contains(sender))
        co_return;

    ready_senders_[p.root_hash].insert(sender);

    // Amplification check
    for (auto action : try_send_ready(p.root_hash))
        co_yield action;

    // NOTE: We do NOT check completion here.
    // Completion requires VALID SIGNATURES, which are handled via on_signature_share.
    // However, if we already have signatures but were waiting for f+1 READYs (unlikely flow),
    // we might check. But safely, on_signature_share drives completion.
}

std::generator<Action> Core::on_signature_share(int sender, const Hash& root, std::vector<std::byte> share)
{
    if (!accept_root(root))
        co_return;

    // Store share
    signature_shares_[root][sender] = share;

    // Check if we can complete
    for (auto action : check_completion(root))
        co_yield action;
}

std::generator<Action> Core::try_send_ready(const Hash& root)
{
    // Thresholds:
    // Echo: N-f (standard RBC)
    // Ready: f+1 (Amplification)

    bool enough_echo = count_echo(root) >= static_cast<size_t>(N_ - f_);
    bool enough_ready = count_ready(root) >= static_cast<size_t>(f_ + 1);

    if ((enough_echo || enough_ready) && !ready_sent_for_[root]) {
        ready_sent_for_[root] = true;
        ready_senders_[root].insert(pid_);

        // For PRBC, we must SIGN the root hash before broadcasting READY.
        // Core cannot sign. Request Service to sign.

        std::vector<std::byte> payload;

        co_yield Action {
            .type = Action::Type::Signal,
            .tag = 1, // SignAndBroadcastReady
            .payload = std::move(payload)
        };
    }
}

std::generator<Action> Core::check_completion(const Hash& root)
{
    if (output_produced_[root])
        co_return;

    // PRBC Termination Condition:
    // 1. Have N-2f shards (can decode)
    // 2. Have 2f+1 valid signatures (can construct proof)

    // Note: Python implementation uses OutputThreshold = N-f (2f+1).
    bool has_enough_shards = can_decode(root);
    bool has_enough_sigs = signature_shares_[root].size() >= static_cast<size_t>(N_ - f_);

    if (has_enough_shards && has_enough_sigs) {
        output_produced_[root] = true;
        std::vector<std::byte> payload;
        co_yield Action { .type = Action::Type::Result, .tag = 2, .payload = std::move(payload) };
    }
}

bool Core::accept_root(const Hash& h) const { return !current_root_ || *current_root_ == h; }

bool Core::is_valid_val(int sender, const ValPayload& p) const
{
    if (sender != leader_)
        return false;
    if (current_root_ && *current_root_ != p.root_hash)
        return false;
    return true;
}

bool Core::can_decode(const Hash& root) const
{
    auto it = stripes_.find(root);
    if (it == stripes_.end())
        return false;
    return it->second.size() >= static_cast<size_t>(N_ - 2 * f_);
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

} // namespace Honey::BFT::PRBC
