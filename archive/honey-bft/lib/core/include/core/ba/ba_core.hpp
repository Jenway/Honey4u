#pragma once
#include "core/common.hpp"
#include <generator>
#include <map>
#include <set>

namespace Honey::BFT::BA {

struct BACoreConfig {
    int session_id;
    int node_id;
    int total_nodes;
    int fault_tolerance;
    int leader_id;
};

struct Action {
    enum class Type : uint8_t {
        BroadcastBval,
        BroadcastAux,
        RequestCoin,
        Output
    } type;

    int round {};
    int value {}; // For Bval, Aux, and Output
    bool decided {}; // If this is a final decision
};

class Core {
public:
    struct RoundState {
        int estimate {};
        std::set<int> bin_values;
        std::set<int> bval_sent;
        bool aux_sent = false;
        bool coin_requested = false;

        // Received messages
        std::set<NodeId> bval_senders[2]; // [0] for val 0, [1] for val 1
        std::map<NodeId, int> aux_msgs; // sender -> value
    };

    explicit Core(const BACoreConfig& config);

    std::generator<Action> start_round(int r, int estimate);
    std::generator<Action> on_bval(int r, NodeId sender, int val);
    std::generator<Action> on_aux(int r, NodeId sender, int val);
    std::generator<Action> on_coin_result(int r, int coin_value);

    [[nodiscard]] int session_id() const { return sid_; }
    [[nodiscard]] int node_id() const { return my_pid_; }
    [[nodiscard]] int current_round() const { return current_r_; }
    [[nodiscard]] bool has_decided() const { return decided_; }

private:
    void ensure_round(int r);
    [[nodiscard]] bool is_ready_for_coin(int r) const;

    int N_, f_, my_pid_, sid_;
    int current_r_ = 0;
    bool decided_ = false;
    std::map<int, RoundState> rounds_;
};

} // namespace Honey::BFT::BA
