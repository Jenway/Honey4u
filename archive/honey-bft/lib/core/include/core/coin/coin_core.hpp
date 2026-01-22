#pragma once

#include "core/coin/messages.hpp"
#include <cstddef>
#include <map>
#include <set>
#include <vector>

namespace Honey::BFT::Coin {

class Core {
public:
    Core(int sid, int pid, int N, int f);

    /**
     * @brief Check if we've already requested this round
     */
    bool has_requested(int round) const;

    /**
     * @brief Mark a round as requested
     */
    void mark_requested(int round);

    /**
     * @brief Add a verified share (driver must verify first)
     * @return true if threshold is now met for this round
     */
    bool add_share(int round, int sender, const SignatureShare& share);

    /**
     * @brief Check if threshold is met for a round
     */
    bool is_threshold_met(int round) const;

    /**
     * @brief Get collected shares for combining
     */
    std::vector<PartialSignature> get_shares(int round) const;

    /**
     * @brief Check if round has finished (output generated)
     */
    bool is_finished(int round) const;

    /**
     * @brief Mark round as finished
     */
    void mark_finished(int round);

    /**
     * @brief Build message payload bytes for a round
     */
    std::vector<std::byte> make_payload_bytes(int round) const;

    // Getters
    int session_id() const { return sid_; }
    int node_id() const { return pid_; }
    int threshold() const { return f_ + 1; }

private:
    int sid_;
    int pid_;
    int N_;
    int f_;

    // State: [Round -> [Sender -> SignatureShare]]
    std::map<int, std::map<int, SignatureShare>> received_;

    // Finished rounds
    std::set<int> finished_;

    // Requested rounds
    std::set<int> requested_;
};

} // namespace Honey::BFT::Coin
