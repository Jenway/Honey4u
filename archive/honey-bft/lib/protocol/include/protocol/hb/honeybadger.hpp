#pragma once
#include "core/hb/messages.hpp"
#include "crypto/threshold/tpke.hpp"
#include "protocol/concepts.hpp"
#include "protocol/hb/concepts.hpp"
#include "protocol/hb/events.hpp"
#include "protocol/runtime/protocol_manager.hpp"
#include "service/network/message_bus.hpp"
#include <deque>
#include <exec/task.hpp>
#include <map>
#include <optional>
#include <set>
#include <stdexec/execution.hpp>
#include <vector>

namespace Honey::BFT::HoneyBadger {

using Honey::BFT::SenderOf;
using Honey::Crypto::Tpke::HybridCiphertext;
using Network::MessageBus;
using Runtime::ProtocolManager;

/**
 * @brief HoneyBadger BFT 协议
 *
 * 使用 Actor 模型架构：
 * - 通过 ProtocolManager 管理 ACS 实例
 * - 通过 MessageBus 广播解密份额
 * - CryptoService 处理加密/解密操作
 */
template <CryptoServiceConcept CryptoSvc>
class HoneyBadger {
public:
    HoneyBadger(const HoneyBadgerConfig& config,
        ProtocolManager& protocol_manager,
        MessageBus& message_bus,
        CryptoSvc& crypto_svc)
        : protocol_manager_(protocol_manager)
        , message_bus_(message_bus)
        , crypto_svc_(crypto_svc)
        , pid_(config.node_id)
        , N_(config.total_nodes)
        , f_(config.fault_tolerance)
        , B_(config.batch_size)
        , threshold_(config.fault_tolerance + 1)
    {
    }

    /**
     * @brief Submit transactions to HoneyBadger
     * @param txs List of transactions
     */
    void submit_transactions(std::vector<std::vector<Byte>> txs)
    {
        for (auto& tx : txs) {
            tx_buffer_.push_back(std::move(tx));
        }
    }

    /**
     * @brief Main run loop processing HoneyBadger events
     * @param in Message stream for incoming HoneyBadger messages
     * @return Task producing blocks
     */
    template <AsyncStreamOf<HBEvent> In>
    auto run(In in) -> exec::task<std::vector<std::vector<std::vector<Byte>>>>
    {
        std::vector<std::vector<std::vector<Byte>>> all_blocks;

        // Start first epoch
        co_await start_new_epoch(0);

        while (auto event_opt = co_await in.next()) {
            HBEvent event = std::move(*event_opt);

            if (auto* acs_ev = std::get_if<ACSCompleteEvent>(&event)) {
                auto block_opt = co_await handle_acs_complete(*acs_ev);
                if (block_opt) {
                    all_blocks.push_back(std::move(*block_opt));

                    // Start next epoch
                    int next_epoch = acs_ev->epoch + 1;
                    co_await start_new_epoch(next_epoch);
                }
            } else if (auto* dec_ev = std::get_if<DecShareReceivedEvent>(&event)) {
                auto block_opt = co_await handle_decryption_share(*dec_ev);
                if (block_opt) {
                    all_blocks.push_back(std::move(*block_opt));

                    // Start next epoch
                    int next_epoch = dec_ev->epoch + 1;
                    co_await start_new_epoch(next_epoch);
                }
            }
        }

        co_return all_blocks;
    }

    /**
     * @brief Check if epoch is complete
     */
    [[nodiscard]] bool is_epoch_complete(int epoch) const
    {
        auto it = epoch_states_.find(epoch);
        return it != epoch_states_.end() && it->second.phase == Phase::Complete;
    }

    /**
     * @brief Get current epoch number
     */
    [[nodiscard]] int current_epoch() const
    {
        return current_epoch_;
    }

private:
    enum class Phase {
        InACS, // Waiting for ACS to complete
        Decrypting, // Collecting decryption shares
        Complete // Block output
    };

    struct EpochState {
        Phase phase;
        std::vector<Byte> encrypted_proposal; // Our encrypted input
        std::vector<std::vector<Byte>> acs_output; // Ciphertexts from ACS
        // Map: ciphertext_idx -> (sender_id -> share_data)
        std::map<int, std::map<int, std::vector<Byte>>> decryption_shares;
        std::map<int, std::vector<Byte>> decrypted_data; // ciphertext_idx -> plaintext
        std::set<int> pending_decryptions; // Which ciphertexts still need decryption
    };

    /**
     * @brief Start a new epoch
     * Step 1: Select transactions
     * Step 2: Encrypt with TPKE
     * Step 3: Serialize ciphertext
     * Step 4: Start ACS
     */
    auto start_new_epoch(int epoch) -> exec::task<void>
    {
        // Check if epoch already started
        if (epoch_states_.contains(epoch))
            co_return;

        // Step 1: Get transactions to propose
        size_t count = std::min(static_cast<size_t>(B_ / N_), tx_buffer_.size());
        std::vector<std::vector<Byte>> txs;
        txs.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            txs.push_back(tx_buffer_[i]);
        }

        // Step 2: Serialize transactions (simplified: concatenate with delimiters)
        std::vector<Byte> plaintext;
        for (const auto& tx : txs) {
            // Add length prefix (4 bytes)
            uint32_t len = static_cast<uint32_t>(tx.size());
            plaintext.push_back(static_cast<Byte>((len >> 24) & 0xFF));
            plaintext.push_back(static_cast<Byte>((len >> 16) & 0xFF));
            plaintext.push_back(static_cast<Byte>((len >> 8) & 0xFF));
            plaintext.push_back(static_cast<Byte>(len & 0xFF));
            plaintext.insert(plaintext.end(), tx.begin(), tx.end());
        }

        // Step 3: Encrypt with TPKE (returns HybridCiphertext)
        auto hybrid_ciphertext = co_await crypto_svc_.async_encrypt(std::span(plaintext));

        // Step 4: Serialize HybridCiphertext for ACS
        std::vector<Byte> serialized_ct;
        serialized_ct.push_back(static_cast<Byte>('E'));
        serialized_ct.push_back(static_cast<Byte>('N'));
        serialized_ct.push_back(static_cast<Byte>('C'));
        serialized_ct.push_back(static_cast<Byte>(':'));
        const auto& v = hybrid_ciphertext.key_ciphertext.v_component;
        serialized_ct.insert(serialized_ct.end(), v.begin(), v.end());

        // Cache the HybridCiphertext for later decryption
        epoch_hybrid_ciphertexts_[epoch] = hybrid_ciphertext;

        // Create epoch state
        epoch_states_[epoch] = EpochState {
            .phase = Phase::InACS,
            .encrypted_proposal = serialized_ct
        };
        current_epoch_ = epoch;

        // Step 5: Start ACS instance through ProtocolManager
        // TODO: ACS 需要通过 ProtocolManager 启动并订阅输出
        // protocol_manager_.create_acs(epoch, serialized_ct);
    }

    /**
     * @brief Broadcast decryption share via MessageBus
     */
    void broadcast_decryption_share(const DecShareMessage& msg)
    {
        // Encode message as Frame and push to MessageBus
        Network::Frame frame {
            .tag = Network::ProtocolTag::HbDecShare,
            .target = -1, // broadcast
            .payload = encode_dec_share_message(msg)
        };
        message_bus_.push(std::move(frame));
    }

    /**
     * @brief Encode DecShareMessage to bytes
     */
    std::vector<Byte> encode_dec_share_message(const DecShareMessage& msg)
    {
        // TODO: Proper serialization
        std::vector<Byte> payload;
        // epoch (4 bytes)
        payload.push_back(static_cast<Byte>((msg.epoch >> 24) & 0xFF));
        payload.push_back(static_cast<Byte>((msg.epoch >> 16) & 0xFF));
        payload.push_back(static_cast<Byte>((msg.epoch >> 8) & 0xFF));
        payload.push_back(static_cast<Byte>(msg.epoch & 0xFF));
        // ciphertext_index (4 bytes)
        payload.push_back(static_cast<Byte>((msg.ciphertext_index >> 24) & 0xFF));
        payload.push_back(static_cast<Byte>((msg.ciphertext_index >> 16) & 0xFF));
        payload.push_back(static_cast<Byte>((msg.ciphertext_index >> 8) & 0xFF));
        payload.push_back(static_cast<Byte>(msg.ciphertext_index & 0xFF));
        // sender_id (4 bytes)
        payload.push_back(static_cast<Byte>((msg.sender_id >> 24) & 0xFF));
        payload.push_back(static_cast<Byte>((msg.sender_id >> 16) & 0xFF));
        payload.push_back(static_cast<Byte>((msg.sender_id >> 8) & 0xFF));
        payload.push_back(static_cast<Byte>(msg.sender_id & 0xFF));
        // share_data
        payload.insert(payload.end(), msg.share_data.begin(), msg.share_data.end());
        return payload;
        break;
    }

case Action::Type::Output:
    // Block output handled in main loop
    break;
}
}

/**
 * @brief Handle ACS completion
 * Cache ciphertexts and generate decryption shares
 */
auto handle_acs_complete(const ACSCompleteEvent& ev) -> exec::task<std::optional<std::vector<std::vector<Byte>>>>
{
    int epoch = ev.epoch;

    // Check if epoch state exists
    if (!epoch_states_.contains(epoch))
        co_return std::nullopt;

    auto& state = epoch_states_[epoch];
    if (state.phase != Phase::InACS)
        co_return std::nullopt;

    // Update state
    state.phase = Phase::Decrypting;
    state.acs_output = ev.ciphertexts;

    // Mark all ciphertexts as pending decryption
    for (size_t j = 0; j < ev.ciphertexts.size(); ++j) {
        state.pending_decryptions.insert(static_cast<int>(j));
    }

    // Cache ciphertexts for later decryption
    epoch_ciphertexts_[epoch] = ev.ciphertexts;

    // Generate and broadcast decryption shares for each ciphertext
    for (size_t j = 0; j < ev.ciphertexts.size(); ++j) {
        auto hct_it = epoch_hybrid_ciphertexts_.find(epoch);
        if (hct_it == epoch_hybrid_ciphertexts_.end()) {
            continue;
        }

        // Generate decryption share
        auto share = co_await crypto_svc_.async_decrypt_share(hct_it->second.key_ciphertext);

        // Serialize DecryptionShare for network transmission
        std::vector<Byte> share_data; // TODO: serialize(share)

        // Broadcast the share via MessageBus
        DecShareMessage msg {
            .epoch = epoch,
            .ciphertext_index = static_cast<int>(j),
            .sender_id = pid_,
            .share_data = share_data
        };
        broadcast_decryption_share(msg);
    }

    co_return std::nullopt;
}

/**
 * @brief Handle decryption share
 * @brief Collect shares and decrypt when threshold reached
 */
auto handle_decryption_share(const DecShareReceivedEvent& ev) -> exec::task<std::optional<std::vector<std::vector<Byte>>>>
{
    int epoch = ev.epoch;
    int ciphertext_idx = ev.ciphertext_index;

    // Check if epoch state exists
    if (!epoch_states_.contains(epoch))
        co_return std::nullopt;

    auto& state = epoch_states_[epoch];
    if (state.phase != Phase::Decrypting)
        co_return std::nullopt;

    // Record the share
    auto& shares_for_ciphertext = state.decryption_shares[ciphertext_idx];

    // Duplicate check
    if (shares_for_ciphertext.contains(ev.sender_id))
        co_return std::nullopt;

    shares_for_ciphertext[ev.sender_id] = ev.share_data;

    // Check if we have enough shares (threshold)
    if (static_cast<int>(shares_for_ciphertext.size()) < threshold_)
        co_return std::nullopt;

    // Mark as ready for decryption
    state.pending_decryptions.erase(ciphertext_idx);

    // Get the cached HybridCiphertext
    auto hct_it = epoch_hybrid_ciphertexts_.find(epoch);
    if (hct_it == epoch_hybrid_ciphertexts_.end()) {
        co_return std::nullopt;
    }

    const auto& hybrid_ciphertext = hct_it->second;

    // Convert shares map to vector of PartialDecryption
    std::vector<PartialDecryption> partial_decryptions;
    for (const auto& [player_id, share_data] : shares_for_ciphertext) {
        // TODO: Deserialize share_data to DecryptionShare (P1 点)
        partial_decryptions.push_back({
            .player_id = player_id,
            .value = Honey::Crypto::bls::P1::identity() // TODO: deserialize
        });
    }

    // Decrypt with collected shares
    auto plaintext_opt = co_await crypto_svc_.async_decrypt(
        hybrid_ciphertext.key_ciphertext,
        std::span(partial_decryptions));

    if (!plaintext_opt) {
        co_return std::nullopt;
    }

    // Submit decrypted data
    state.decrypted_data[ciphertext_idx] = *plaintext_opt;

    // Try to output block if all ciphertexts are decrypted
    if (state.decrypted_data.size() != state.acs_output.size())
        co_return std::nullopt;

    if (state.phase == Phase::Complete)
        co_return std::nullopt;

    state.phase = Phase::Complete;

    // Collect all decrypted transactions
    std::vector<std::vector<Byte>> block;
    for (const auto& [idx, data] : state.decrypted_data) {
        block.push_back(data);
    }

    // Remove from buffer
    size_t to_remove = std::min(static_cast<size_t>(B_), tx_buffer_.size());
    tx_buffer_.erase(tx_buffer_.begin(), tx_buffer_.begin() + to_remove);

    // Clean up cached ciphertexts
    epoch_ciphertexts_.erase(epoch);
    epoch_hybrid_ciphertexts_.erase(epoch);

    co_return block;
}

ProtocolManager & protocol_manager_;
MessageBus & message_bus_;
CryptoSvc & crypto_svc_;

// Config
int pid_;
int N_;
int f_;
int B_; // Batch size
int threshold_; // f+1 shares needed for decryption

// State
int current_epoch_ = 0;
std::deque<std::vector<Byte>> tx_buffer_; // Transaction buffer
std::map<int, EpochState> epoch_states_; // Per-epoch state

// Cache ciphertexts from ACS for decryption (serialized bytes)
std::map<int, std::vector<std::vector<Byte>>> epoch_ciphertexts_;

// Cache HybridCiphertext structures (type-safe, for decryption)
std::map<int, HybridCiphertext> epoch_hybrid_ciphertexts_;
}
;

} // namespace Honey::BFT::HoneyBadger
