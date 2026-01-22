#pragma once
#include "core/common.hpp"
#include <map>
#include <optional>
#include <set>

namespace Honey::BFT::BA {

struct BACoreConfig {
    int session_id;
    int node_id;
    int total_nodes;
    int fault_tolerance;
    NodeId leader_id;
};

class BACore {
public:
    struct RoundState {
        int estimate;
        std::set<int> bin_values;
        std::set<int> bval_sent;
        bool aux_sent = false;

        // 收到的消息存储
        std::map<NodeId, int> bval_counts[2]; // [0] counts for val 0, [1] for val 1
        std::set<NodeId> bval_senders[2]; // 防止重复计数
        std::map<NodeId, int> aux_msgs; // sender -> value
    };

    BACore(const BACoreConfig& config)
        : N_(config.total_nodes)
        , f_(config.fault_tolerance)
        , my_pid_(config.node_id)
        , leader_id_(config.leader_id)
    {
    }

    // === 1. 状态更新 (Observations) ===

    void start_round(int r, int estimate)
    {
        ensure_round(r);
        rounds_[r].estimate = estimate;
    }

    void observe_bval(int r, NodeId sender, int val)
    {
        if (val != 0 && val != 1)
            return;
        ensure_round(r);
        auto& rs = rounds_[r];

        if (rs.bval_senders[val].contains(sender))
            return; // 重复消息
        rs.bval_senders[val].insert(sender);

        // 逻辑：更新计数
        int count = rs.bval_senders[val].size();

        //  upon receiving BVALr(b) messages from 2 f + 1 nodes,
        //  bin\_values_r := bin\_values_r ∪ {b}
        if (count >= (2 * f_) + 1) {
            rs.bin_values.insert(val);
        }
    }

    void observe_aux(int r, NodeId sender, int val)
    {
        if (val != 0 && val != 1)
            return;
        ensure_round(r);
        rounds_[r].aux_msgs[sender] = val;
    }

    //  upon receiving BVAL_r(b) messages from f + 1 nodes,
    //  if BVAL_r(b) has not been sent, multicast BVAL_r(b)
    [[nodiscard]] bool should_multicast_bval(int r, int val) const
    {
        if (!has_round(r))
            return false;
        const auto& rs = rounds_.at(r);

        bool received_f_plus_1 = rs.bval_senders[val].size() >= (f_ + 1);
        bool not_sent_yet = !rs.bval_sent.contains(val);

        return received_f_plus_1 && not_sent_yet;
    }

    //    – wait until bin\_values_r  != /0, then
    // - multicast AUX_r(w) where w ∈ bin\_values_r
    [[nodiscard]] std::optional<int> should_multicast_aux(int r) const
    {
        if (!has_round(r))
            return std::nullopt;
        const auto& rs = rounds_.at(r);

        if (!rs.aux_sent && !rs.bin_values.empty()) {
            return *rs.bin_values.begin(); // 返回 w
        }
        return std::nullopt;
    }

    // - wait until at least (N − f ) AUXr messages have been received,
    // such that the set of values carried by these messages,
    // vals are a subset of bin_valuesr
    // (note that bin_valuesr may continue to change as BVALr messages are received,
    // thus this condition may be triggered upon
    [[nodiscard]] bool is_ready_for_coin(int r) const
    {
        if (!has_round(r))
            return false;
        const auto& rs = rounds_.at(r);

        // 还没收到足够的 AUX
        if (rs.aux_msgs.size() < (N_ - f_))
            return false;

        int valid_aux_count = 0;
        for (auto [sender, val] : rs.aux_msgs) {
            if (rs.bin_values.contains(val)) {
                valid_aux_count++;
            }
        }

        return valid_aux_count >= (N_ - f_);
    }

    struct StepResult {
        int next_estimate {};
        std::optional<int> decision;
    };

    // Algorithm: Coin flip logic
    StepResult advance_round_with_coin(int r, int s)
    {
        auto& rs = rounds_.at(r);

        // 计算 vals: 所有有效的 AUX 值
        std::set<int> vals;
        for (auto [sender, val] : rs.aux_msgs) {
            if (rs.bin_values.contains(val)) {
                vals.insert(val);
            }
        }

        int next_est;
        std::optional<int> output;

        // "if vals = {b}"
        if (vals.size() == 1) {
            int b = *vals.begin();
            next_est = b;
            // "if b = s%2 then output b"
            if (b == (s % 2)) {
                if (!decided_) {
                    decided_ = true;
                    output = b;
                }
            }
        } else {
            // "else est = s%2"
            next_est = s % 2;
        }

        return { .next_estimate = next_est, .decision = output };
    }

    void mark_bval_sent(int r, int val) { rounds_[r].bval_sent.insert(val); }
    void mark_aux_sent(int r) { rounds_[r].aux_sent = true; }
    [[nodiscard]] int get_current_round() const { return current_r_; }

private:
    void ensure_round(int r)
    {
        if (!rounds_.contains(r)) {
            rounds_[r] = RoundState {};
        }
    }
    [[nodiscard]] bool has_round(int r) const { return rounds_.contains(r); }

    int N_, f_, my_pid_;
    NodeId leader_id_;
    int current_r_ = 0;
    bool decided_ = false;
    std::map<int, RoundState> rounds_;
};

} // namespace Honey::BFT::BA
