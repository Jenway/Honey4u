#pragma once

#include "core/rbc/concept.hpp"
#include "core/rbc/messages.hpp"
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <vector>

namespace Honey::BFT::RBC {

struct RBCConfig {
    int session_id;
    int node_id;
    int total_nodes;
    int fault_tolerance;
    int leader_id;
};

class RBCCore {
public:
    explicit RBCCore(const RBCConfig& config)
        : sid_(config.session_id)
        , pid_(config.node_id)
        , N_(config.total_nodes)
        , f_(config.fault_tolerance)
        , leader_(config.leader_id)
    {
    }

    [[nodiscard]] bool is_leader(NodeId pid) const { return pid == leader_; }

    [[nodiscard]] bool is_valid_val(int sender, const ValPayload& p) const
    {
        // Only the leader may send VAL, and any subsequent VAL must match the chosen root.
        if (sender != leader_)
            return false;
        if (current_root_ && *current_root_ != p.root_hash)
            return false;
        return true;
    }
    [[nodiscard]] bool is_valid_echo(int sender, const EchoPayload& p) const
    {
        // 验证 Echo 消息的合法性 (如有需要)
        return true; // 占位实现
    }

    void observe_val(int sender, const ValPayload& p)
    {
        // 处理 Val 消息，更新状态
        if (!current_root_) {
            current_root_ = p.root_hash;
        }
        // The VAL stripe is targeted for this node, so store it under our own id.
        stripes_[p.root_hash][pid_] = p.stripe;
    }
    void observe_echo(int sender, const EchoPayload& p)
    {
        // 处理 Echo 消息，更新状态
        echo_senders_[p.root_hash].insert(sender);
        stripes_[p.root_hash][sender] = p.stripe;
    }
    void observe_ready(int sender, const ReadyPayload& p)
    {
        // 处理 Ready 消息，更新状态
        ready_senders_[p.root_hash].insert(sender);
    }

    bool has_received_val() const { return current_root_.has_value(); }
    bool has_sent_echo() const { return echo_sent_; }
    bool has_sent_ready() const { return ready_sent_; }

    auto count_echo(const Hash& root) const -> int
    {
        auto it = echo_senders_.find(root);
        if (it != echo_senders_.end()) {
            return static_cast<int>(it->second.size());
        }
        return 0;
    }
    auto count_ready(const Hash& root) const -> int
    {
        auto it = ready_senders_.find(root);
        if (it != ready_senders_.end()) {
            return static_cast<int>(it->second.size());
        }
        return 0;
    }
    auto count_shards(const Hash& root) const -> int
    {
        auto it = stripes_.find(root);
        if (it != stripes_.end()) {
            return static_cast<int>(it->second.size());
        }
        return 0;
    }
    // 核心算法阈值判断
    bool should_send_ready() const
    {
        // Algorithm: N-f ECHO or f+1 READY
        if (!current_root_)
            return false;
        auto root = *current_root_;
        return (count_echo(root) >= N_ - f_) || (count_ready(root) >= f_ + 1);
    }

    bool can_output() const
    {
        // Algorithm: 2f+1 READY and N-2f Shards
        if (!current_root_)
            return false;
        auto root = *current_root_;
        return (count_ready(root) >= (2 * f_) + 1) && (count_shards(root) >= N_ - 2 * f_);
    }

    // 辅助获取数据
    const std::map<NodeId, std::vector<Byte>>& get_shards() const
    {
        if (!current_root_) {
            throw std::runtime_error("No current root set");
        }
        auto root = *current_root_;
        return stripes_.at(root);
    }
    Hash get_current_root() const
    {
        if (!current_root_) {
            throw std::runtime_error("No current root set");
        }
        return *current_root_;
    }

    void mark_echo_sent()
    {
        echo_sent_ = true;
        if (current_root_) {
            echo_senders_[*current_root_].insert(pid_);
        }
    }
    void mark_ready_sent()
    {
        ready_sent_ = true;
        if (current_root_) {
            ready_senders_[*current_root_].insert(pid_);
        }
    }

private:
    // 配置参数
    int sid_, pid_, N_, f_, leader_;

    // 状态
    // current_root_ 一旦设置就不会更改
    bool echo_sent_ = false;
    bool ready_sent_ = false;

    std::optional<Hash> current_root_;

    std::map<Hash, std::map<int, std::vector<Byte>>> stripes_;
    std::map<Hash, std::set<int>> echo_senders_;
    std::map<Hash, std::set<int>> ready_senders_;
};

} // namespace Honey::BFT::RBC
