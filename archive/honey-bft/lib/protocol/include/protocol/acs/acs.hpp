#pragma once
#include "core/common.hpp"
#include "protocol/acs/concepts.hpp"
#include "protocol/acs/events.hpp"
#include "protocol/acs/messages.hpp"
#include "protocol/concepts.hpp"
#include "protocol/runtime/protocol_manager.hpp"
#include <exec/task.hpp>
#include <map>
#include <set>

namespace Honey::BFT::ACS {

using Runtime::ProtocolManager;

/**
 * @brief ACS (Asynchronous Common Subset) 协议
 *
 * 使用 Actor 模型架构：
 * - 通过 ProtocolManager 管理 N 个 RBC 和 N 个 BA 实例
 * - 每个实例是独立的 actor，通过消息通信
 * - ACS 负责协调逻辑和事件路由
 */
class ACS {
public:
    ACS(int session_id, int my_pid, ProtocolManager& manager)
        : session_id_(session_id)
        , my_pid_(my_pid)
        , manager_(manager)
        , N_(manager.system_context().N)
        , f_(manager.system_context().f)
    {
    }

    // ACS Run now accepts a unified Event Stream
    // It doesn't need to know how "Channel" is implemented, as long as it can next() out Event
    template <AsyncStreamOf<ACSEvent> EventStream>
    auto run(std::vector<Byte> my_input, EventStream stream)
        -> exec::task<std::vector<std::vector<Byte>>>
    {
        // 1. Start all RBCs
        for (int i = 0; i < N_; ++i) {
            if (i == my_pid_) {
                manager_.create_rbc(session_id_, i, my_input);
            } else {
                manager_.create_rbc(session_id_, i, std::nullopt);
            }
        }

        // 2. Event loop
        while (auto event_opt = co_await stream.next()) {
            ACSEvent event = std::move(*event_opt);

            if (auto* net_ev = std::get_if<NetworkMsgEvent>(&event)) {
                handle_network(*net_ev);
            } else if (auto* rbc_ev = std::get_if<RbcDoneEvent>(&event)) {
                handle_rbc_done(*rbc_ev);
            } else if (auto* ba_ev = std::get_if<BaDoneEvent>(&event)) {
                handle_ba_done(*ba_ev);
            }

            // Check if finished
            if (is_complete()) {
                // Collect output: RBC values where BA decided 1
                co_return get_output();
            }
        }

        co_return std::vector<std::vector<Byte>> {};
    }

    [[nodiscard]] bool is_complete() const { return output_triggered_; }

private:
    [[nodiscard]] std::vector<std::vector<Byte>> get_output() const
    {
        std::vector<std::vector<Byte>> result;
        for (const auto& [idx, dec] : ba_decisions_) {
            if (dec == 1 && rbc_data_.contains(idx)) {
                result.push_back(rbc_data_.at(idx));
            }
        }
        return result;
    }

    void handle_network(const NetworkMsgEvent& ev)
    {
        // ACS is just routing
        if (ev.is_rbc) {
            manager_.dispatch_rbc_message(session_id_, ev.instance_id, ev.sender, ev.payload);
        } else {
            manager_.dispatch_ba_message(session_id_, ev.instance_id, ev.sender, ev.payload);
        }
    }

    void handle_rbc_done(const RbcDoneEvent& ev)
    {
        int index = ev.instance_id;

        if (rbc_completed_.contains(index))
            return;

        rbc_completed_.insert(index);
        rbc_data_[index] = ev.data;

        // If haven't proposed to this BA yet, propose 1
        if (!ba_input_decided_.contains(index)) {
            ba_input_decided_[index] = 1;
            manager_.create_ba(session_id_, index);
            manager_.input_to_ba(session_id_, index, 1);
        }
    }

    void handle_ba_done(const BaDoneEvent& ev)
    {
        int index = ev.instance_id;
        int decision = ev.decision;

        if (ba_completed_.contains(index))
            return;

        ba_completed_.insert(index);
        ba_decisions_[index] = decision;

        if (decision == 1) {
            ba_yes_count_++;
        }

        // Check if we've reached N-f BA instances with decision 1
        if (ba_yes_count_ >= (N_ - f_) && !vote_0_triggered_) {
            vote_0_triggered_ = true;

            // Propose 0 to all BA instances that haven't received input yet
            for (int i = 0; i < N_; ++i) {
                if (!ba_input_decided_.contains(i)) {
                    ba_input_decided_[i] = 0;
                    manager_.create_ba(session_id_, i);
                    manager_.input_to_ba(session_id_, i, 0);
                }
            }
        }

        // Check if all BA instances have completed
        if (static_cast<int>(ba_completed_.size()) == N_) {
            output_triggered_ = true;
        }
    }

    int session_id_;
    int my_pid_;
    ProtocolManager& manager_;
    int N_;
    int f_;

    // RBC state
    std::set<int> rbc_completed_;
    std::map<int, std::vector<Byte>> rbc_data_;

    // BA state
    std::map<int, int> ba_input_decided_; // What we proposed to BA j
    std::set<int> ba_completed_; // Which BA instances completed
    std::map<int, int> ba_decisions_; // BA decisions

    int ba_yes_count_ = 0;
    bool vote_0_triggered_ = false;
    bool output_triggered_ = false;
};

} // namespace Honey::BFT::ACS
