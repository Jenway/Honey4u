#include "core/hb/honeybadger_core.hpp"

namespace Honey::BFT::HoneyBadger {

Core::Core(const HoneyBadgerConfig& config)
    : pid_(config.node_id)
    , N_(config.total_nodes)
    , f_(config.fault_tolerance)
    , B_(config.batch_size)
    , threshold_(config.fault_tolerance + 1) // f+1 shares needed
{
}

void Core::submit_transactions(std::vector<std::vector<Byte>> txs)
{
    for (auto& tx : txs) {
        tx_buffer_.push_back(std::move(tx));
    }
}

std::generator<Action> Core::start_epoch(int epoch, std::vector<Byte> encrypted_proposal)
{
    if (epoch_states_.contains(epoch))
        co_return;

    epoch_states_[epoch] = EpochState {
        .phase = Phase::InACS,
        .encrypted_proposal = std::move(encrypted_proposal)
    };

    current_epoch_ = epoch;

    co_yield Action {
        .type = Action::Type::StartACS,
        .epoch = epoch,
        .acs_input = epoch_states_[epoch].encrypted_proposal
    };
}

std::generator<Action> Core::on_acs_complete(int epoch,
    std::vector<std::vector<Byte>> ciphertexts)
{
    if (!epoch_states_.contains(epoch))
        co_return;

    auto& state = epoch_states_[epoch];
    if (state.phase != Phase::InACS)
        co_return;

    state.phase = Phase::Decrypting;
    state.acs_output = std::move(ciphertexts);

    // For each ciphertext, we need to broadcast our decryption share
    // Note: Actual share generation is done by Service layer (Crypto)
    // Here we just track that we need to do it
    for (size_t j = 0; j < state.acs_output.size(); ++j) {
        state.pending_decryptions.insert(static_cast<int>(j));
    }
}

std::generator<Action> Core::broadcast_decryption_share(int epoch,
    int ciphertext_idx,
    std::vector<Byte> share_data)
{
    if (!epoch_states_.contains(epoch))
        co_return;

    auto& state = epoch_states_[epoch];
    if (state.phase != Phase::Decrypting)
        co_return;

    co_yield Action {
        .type = Action::Type::BroadcastDecShare,
        .epoch = epoch,
        .dec_share_msg = DecryptionShareMsg {
            .epoch = epoch,
            .ciphertext_index = ciphertext_idx,
            .sender_id = pid_,
            .share_data = std::move(share_data) }
    };
}

bool Core::on_decryption_share(const DecryptionShareMsg& msg)
{
    if (!epoch_states_.contains(msg.epoch))
        return false;

    auto& state = epoch_states_[msg.epoch];
    if (state.phase != Phase::Decrypting)
        return false;

    // Track shares: map[ciphertext_idx][sender_id] = share_data
    auto& shares_for_ciphertext = state.decryption_shares[msg.ciphertext_index];

    // Duplicate check
    if (shares_for_ciphertext.contains(msg.sender_id))
        return false;

    shares_for_ciphertext[msg.sender_id] = msg.share_data;
    return true;
}

std::optional<std::map<int, std::vector<Byte>>>
Core::get_shares_if_ready(int epoch, int ciphertext_idx)
{
    if (!epoch_states_.contains(epoch))
        return std::nullopt;

    auto& state = epoch_states_[epoch];
    auto it = state.decryption_shares.find(ciphertext_idx);
    if (it == state.decryption_shares.end())
        return std::nullopt;

    // Check if we have at least threshold shares
    if (static_cast<int>(it->second.size()) < threshold_)
        return std::nullopt;

    // Mark as ready for decryption
    state.pending_decryptions.erase(ciphertext_idx);

    // Return shares for Service layer to decrypt
    return it->second;
}

std::optional<std::vector<Byte>> Core::get_ciphertext(int epoch, int ciphertext_idx) const
{
    auto it = epoch_states_.find(epoch);
    if (it == epoch_states_.end())
        return std::nullopt;

    const auto& state = it->second;
    if (ciphertext_idx >= static_cast<int>(state.acs_output.size()))
        return std::nullopt;

    return state.acs_output[ciphertext_idx];
}

void Core::on_decrypted(int epoch, int ciphertext_idx, std::vector<Byte> plaintext)
{
    if (!epoch_states_.contains(epoch))
        return;

    auto& state = epoch_states_[epoch];
    state.decrypted_data[ciphertext_idx] = std::move(plaintext);
}

std::generator<Action> Core::try_output(int epoch)
{
    if (!epoch_states_.contains(epoch))
        co_return;

    auto& state = epoch_states_[epoch];

    // Check if all ciphertexts have been decrypted
    if (state.decrypted_data.size() != state.acs_output.size())
        co_return;

    if (state.phase == Phase::Complete)
        co_return;

    state.phase = Phase::Complete;

    // Collect all decrypted transactions
    std::vector<std::vector<Byte>> block;
    for (const auto& [idx, data] : state.decrypted_data) {
        // Note: In real implementation, parse data as list of transactions
        block.push_back(data);
    }

    // Remove from buffer (simplified: in real impl, need proper deduplication)
    // buf := buf - block_r
    // For now, just clear first B elements
    size_t to_remove = std::min(static_cast<size_t>(B_), tx_buffer_.size());
    tx_buffer_.erase(tx_buffer_.begin(), tx_buffer_.begin() + to_remove);

    co_yield Action {
        .type = Action::Type::Output,
        .epoch = epoch,
        .output_block = std::move(block)
    };
}

std::vector<std::vector<Byte>> Core::get_proposal_transactions() const
{
    size_t count = std::min(static_cast<size_t>(B_ / N_), tx_buffer_.size());
    std::vector<std::vector<Byte>> result;
    result.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        result.push_back(tx_buffer_[i]);
    }
    return result;
}

bool Core::is_epoch_complete(int epoch) const
{
    auto it = epoch_states_.find(epoch);
    return it != epoch_states_.end() && it->second.phase == Phase::Complete;
}

} // namespace Honey::BFT::HoneyBadger
