#pragma once

#include "core/coin/messages.hpp"
#include <cstddef>
#include <generator>
#include <map>
#include <set>
#include <span>
#include <vector>

namespace Honey::BFT::Coin {

struct CoinConfig {
    int session_id;
    int node_id;
    int total_nodes;
    int fault_tolerance;
    int leader_id;
};

struct Action {
    enum class Type : uint8_t {
        BroadcastShare,
        CombineSignatures,
        Output
    } type;

    int round {};
    SignatureShare my_share {};
    std::span<const PartialSignature> shares_to_combine {};
    uint8_t output_bit {};
};

class Core {
public:
    explicit Core(const CoinConfig& config);

    std::generator<Action> request_coin(int round, const SignatureShare& my_share);
    std::generator<Action> on_share(int round, int sender, const SignatureShare& share);
    void mark_finished(int round, uint8_t bit);

    [[nodiscard]] bool is_finished(int round) const
    {
        return finished_.contains(round);
    }

    [[nodiscard]] uint8_t get_output(int round) const
    {
        return outputs_.at(round);
    }

    [[nodiscard]] std::vector<std::byte> make_payload_bytes(int round) const;

    [[nodiscard]] int session_id() const { return sid_; }
    [[nodiscard]] int node_id() const { return pid_; }
    [[nodiscard]] int threshold() const { return f_ + 1; }

private:
    std::generator<Action> try_combine(int round);

    int sid_, pid_, N_, f_;

    // State: [Round -> [Sender -> SignatureShare]]
    std::map<int, std::map<int, SignatureShare>> received_;

    // Finished rounds and their outputs
    std::set<int> finished_;
    std::map<int, uint8_t> outputs_;

    // Requested rounds
    std::set<int> requested_;

    // Track if combination has been triggered
    std::map<int, bool> combination_triggered_;
};

} // namespace Honey::BFT::Coin
