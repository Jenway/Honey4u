#pragma once
#include "core/hb/honeybadger_core.hpp"
#include "crypto/threshold/tpke.hpp"
#include "service/concepts.hpp"
#include "service/hb/concepts.hpp"
#include "service/hb/events.hpp"
#include <exec/task.hpp>
#include <map>
#include <optional>
#include <stdexec/execution.hpp>
#include <vector>

namespace Honey::BFT::HoneyBadger {

using Action = Honey::BFT::HoneyBadger::Action;
using Core = Honey::BFT::HoneyBadger::Core;
using Honey::BFT::SenderOf;
using Honey::Crypto::Tpke::HybridCiphertext;

template <Transceiver T, ACSServiceConcept ACSSvc, CryptoServiceConcept CryptoSvc>
class HoneyBadger {
public:
    HoneyBadger(const HoneyBadgerConfig& config,
        T& transport,
        ACSSvc& acs_svc,
        CryptoSvc& crypto_svc)
        : core_(config)
        , transport_(transport)
        , acs_svc_(acs_svc)
        , crypto_svc_(crypto_svc)
        , N_(config.total_nodes)
        , my_pid_(config.node_id)
    {
    }

    /**
     * @brief Submit transactions to HoneyBadger
     * @param txs List of transactions
     */
    void submit_transactions(std::vector<std::vector<Byte>> txs)
    {
        core_.submit_transactions(std::move(txs));
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
        return core_.is_epoch_complete(epoch);
    }

    /**
     * @brief Get current epoch number
     */
    [[nodiscard]] int current_epoch() const
    {
        return core_.current_epoch();
    }

private:
    /**
     * @brief Start a new epoch
     * Step 1: Select transactions
     * Step 2: Encrypt with TPKE
     * Step 3: Serialize ciphertext
     * Step 4: Start ACS
     */
    auto start_new_epoch(int epoch) -> exec::task<void>
    {
        // Step 1: Get transactions to propose
        auto txs = core_.get_proposal_transactions();

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
        // TODO: 这里需要序列化，但是由 HoneyBadger Service 负责，不是 TPKEService
        // 暂时简化：创建一个 placeholder 格式
        std::vector<Byte> serialized_ct;
        serialized_ct.push_back(static_cast<Byte>('E'));
        serialized_ct.push_back(static_cast<Byte>('N'));
        serialized_ct.push_back(static_cast<Byte>('C'));
        serialized_ct.push_back(static_cast<Byte>(':'));
        // 添加 v_component 作为占位符
        const auto& v = hybrid_ciphertext.key_ciphertext.v_component;
        serialized_ct.insert(serialized_ct.end(), v.begin(), v.end());

        // Cache the HybridCiphertext for later decryption
        epoch_hybrid_ciphertexts_[epoch] = hybrid_ciphertext;

        // Step 5: Start epoch in core and handle actions
        for (auto action : core_.start_epoch(epoch, serialized_ct)) {
            co_await handle_action(action);
        }
    }

    auto handle_action(const Action& action) -> exec::task<void>
    {
        switch (action.type) {
        case Action::Type::StartACS:
            // Start ACS with our encrypted proposal
            co_await acs_svc_.start_acs(action.epoch, action.acs_input);
            break;

        case Action::Type::BroadcastDecShare: {
            // Serialize and broadcast decryption share message
            // In real implementation, need proper message serialization
            DecShareMessage msg {
                .epoch = action.dec_share_msg.epoch,
                .ciphertext_index = action.dec_share_msg.ciphertext_index,
                .sender_id = action.dec_share_msg.sender_id,
                .share_data = action.dec_share_msg.share_data
            };
            co_await transport_.broadcast(msg);
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
        // Cache ciphertexts for later decryption
        epoch_ciphertexts_[ev.epoch] = ev.ciphertexts;

        // Notify core about ACS completion
        for (auto action : core_.on_acs_complete(ev.epoch, ev.ciphertexts)) {
            co_await handle_action(action);
        }

        // Generate and broadcast decryption shares for each ciphertext
        for (size_t j = 0; j < ev.ciphertexts.size(); ++j) {
            // TODO: Deserialize ev.ciphertexts[j] to Ciphertext
            // For now, use the cached HybridCiphertext
            auto hct_it = epoch_hybrid_ciphertexts_.find(ev.epoch);
            if (hct_it == epoch_hybrid_ciphertexts_.end()) {
                continue; // Skip if not found
            }

            // Generate decryption share (返回 DecryptionShare / P1 点)
            auto share = co_await crypto_svc_.async_decrypt_share(hct_it->second.key_ciphertext);

            // Serialize DecryptionShare for network transmission
            // TODO: serialize(share) -> std::vector<Byte>
            std::vector<Byte> share_data; // Placeholder

            // Broadcast the share
            for (auto action : core_.broadcast_decryption_share(
                     ev.epoch, static_cast<int>(j), share_data)) {
                co_await handle_action(action);
            }
        }

        // Check if we can output (unlikely at this point)
        for (auto action : core_.try_output(ev.epoch)) {
            if (action.type == Action::Type::Output) {
                co_return action.output_block;
            }
        }

        co_return std::nullopt;
    }

    /**
     * @brief Handle decryption share
     * @brief Collect shares and decrypt when threshold reached
     */
    auto handle_decryption_share(const DecShareReceivedEvent& ev) -> exec::task<std::optional<std::vector<std::vector<Byte>>>>
    {
        // Record the share
        DecryptionShareMsg msg {
            .epoch = ev.epoch,
            .ciphertext_index = ev.ciphertext_index,
            .sender_id = ev.sender_id,
            .share_data = ev.share_data
        };

        bool is_new = core_.on_decryption_share(msg);
        if (!is_new) {
            co_return std::nullopt; // Duplicate share
        }

        // Try to get shares if threshold reached
        auto shares_map_opt = core_.get_shares_if_ready(ev.epoch, ev.ciphertext_index);
        if (!shares_map_opt.has_value()) {
            co_return std::nullopt; // Not enough shares yet
        }

        // Get the cached HybridCiphertext
        auto hct_it = epoch_hybrid_ciphertexts_.find(ev.epoch);
        if (hct_it == epoch_hybrid_ciphertexts_.end()) {
            co_return std::nullopt; // Shouldn't happen
        }

        const auto& hybrid_ciphertext = hct_it->second;

        // Convert shares map to vector of PartialDecryption
        std::vector<PartialDecryption> partial_decryptions;
        for (const auto& [player_id, share_data] : *shares_map_opt) {
            // TODO: Deserialize share_data to DecryptionShare (P1 点)
            // For now, use identity point
            partial_decryptions.push_back({
                .player_id = player_id,
                .value = Honey::Crypto::bls::P1::identity() // TODO: deserialize(share_data)
            });
        }

        // Decrypt with collected shares
        auto plaintext_opt = co_await crypto_svc_.async_decrypt(
            hybrid_ciphertext.key_ciphertext,
            std::span(partial_decryptions));

        if (!plaintext_opt) {
            co_return std::nullopt; // Decryption failed
        }

        // Submit decrypted data
        core_.on_decrypted(ev.epoch, ev.ciphertext_index, *plaintext_opt);

        // Try to output block if all ciphertexts are decrypted
        for (auto action : core_.try_output(ev.epoch)) {
            if (action.type == Action::Type::Output) {
                // Clean up cached ciphertexts
                epoch_ciphertexts_.erase(ev.epoch);
                epoch_hybrid_ciphertexts_.erase(ev.epoch);
                co_return action.output_block;
            }
        }

        co_return std::nullopt;
    }

    Core core_;
    T& transport_;
    ACSSvc& acs_svc_;
    CryptoSvc& crypto_svc_;
    int N_;
    int my_pid_;

    // Cache ciphertexts from ACS for decryption (serialized bytes)
    std::map<int, std::vector<std::vector<Byte>>> epoch_ciphertexts_;

    // Cache HybridCiphertext structures (type-safe, for decryption)
    std::map<int, HybridCiphertext> epoch_hybrid_ciphertexts_;
};

} // namespace Honey::BFT::HoneyBadger
