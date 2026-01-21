#pragma once

#include "core/rbc/messages.hpp"
#include <generator>
#include <map>
#include <optional>
#include <set>
#include <vector>

namespace Honey::BFT::RBC {

struct Effect {
    enum class Type : uint8_t {
        Broadcast,
        SendTo,
        Deliver
    } type {};

    int target_pid = -1; // 仅 SendTo 有效

    // 用于 Broadcast 和 SendTo
    std::optional<RBCMessage> msg;

    // 用于 PrepareAndSendVal 和 Deliver
    std::optional<Hash> root_hash;
};

struct RBCConfig {
    int session_id;
    int node_id;
    int total_nodes;
    int fault_tolerance;
    int leader_id;
};

class RBCCore {
public:
    explicit RBCCore(const RBCConfig& config);

    std::generator<Effect> handle_message(RBCMessage msg);

    [[nodiscard]] const std::map<NodeId, std::vector<Byte>>& get_shards_for_root(const Hash& root) const;

private:
    std::generator<Effect> handle_val(int sender, ValPayload p);
    std::generator<Effect> handle_echo(int sender, EchoPayload p);
    std::generator<Effect> handle_ready(int sender, ReadyPayload p);
    std::generator<Effect> check_delivery(Hash root);

    // 配置参数
    int sid_, pid_, N_, f_, leader_;
    int K_, EchoThreshold_, ReadyThreshold_, OutputThreshold_;

    // 状态
    std::optional<Hash> from_leader_hash_;
    std::map<Hash, std::map<int, std::vector<Byte>>> stripes_;
    std::map<Hash, std::set<int>> echo_senders_;
    std::map<Hash, std::set<int>> ready_senders_;
    std::map<Hash, bool> ready_sent_;
    std::map<Hash, bool> delivered_;
};

} // namespace Honey::BFT::RBC
