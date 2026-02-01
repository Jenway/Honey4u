#pragma once
#include "core/hb/messages.hpp"
#include <deque>
#include <generator>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <vector>

namespace Honey::BFT::HoneyBadger {

struct HoneyBadgerConfig {
    int node_id;
    int total_nodes;
    int fault_tolerance;
    int batch_size; // B parameter
};

struct Action {
    enum class Type : uint8_t {
        StartACS, // Start ACS for current epoch
        BroadcastDecShare, // Broadcast decryption share
        Output // Block ready for output
    } type;

    int epoch {}; // Which epoch this action belongs to
    std::vector<Byte> acs_input {}; // Encrypted proposal for ACS
    DecryptionShareMsg dec_share_msg {}; // Decryption share to broadcast
    std::vector<std::vector<Byte>> output_block {}; // Final block
};

class Core {
public:
    explicit Core(const HoneyBadgerConfig& config);

    void submit_transactions(std::vector<std::vector<Byte>> txs);

    std::generator<Action> start_epoch(int epoch, std::vector<Byte> encrypted_proposal);

    std::generator<Action> on_acs_complete(int epoch,
        std::vector<std::vector<Byte>> ciphertexts);

    std::generator<Action> broadcast_decryption_share(int epoch,
        int ciphertext_idx,
        std::vector<Byte> share_data);

    bool on_decryption_share(const DecryptionShareMsg& msg);

    std::optional<std::map<int, std::vector<Byte>>>
    get_shares_if_ready(int epoch, int ciphertext_idx);

    std::optional<std::vector<Byte>> get_ciphertext(int epoch, int ciphertext_idx) const;

    void on_decrypted(int epoch, int ciphertext_idx, std::vector<Byte> plaintext);

    std::generator<Action> try_output(int epoch);

    [[nodiscard]] int node_id() const { return pid_; }
    [[nodiscard]] int current_epoch() const { return current_epoch_; }
    [[nodiscard]] size_t buffer_size() const { return tx_buffer_.size(); }
    [[nodiscard]] bool is_epoch_complete(int epoch) const;

    std::vector<std::vector<Byte>> get_proposal_transactions() const;

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

    int pid_;
    int N_;
    int f_;
    int B_; // Batch size
    int threshold_; // f+1 shares needed for decryption

    int current_epoch_ = 0;
    std::deque<std::vector<Byte>> tx_buffer_; // Transaction buffer
    std::map<int, EpochState> epoch_states_; // Per-epoch state
};

} // namespace Honey::BFT::HoneyBadger
