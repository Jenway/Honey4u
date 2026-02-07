#pragma once

#include "core/common.hpp"
#include "core/rbc/messages.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <generator>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <vector>

namespace Honey::BFT::RBC {

struct RBCConfig {
    int session_id;
    int node_id;
    int total_nodes;
    int fault_tolerance;
    int leader_id;
};

struct Action {
    enum class Type : uint8_t {
        BroadcastEcho,
        BroadcastReady,
        Decode,
        Output
    } type {};

    Hash root_hash {};

    std::span<const std::byte> my_stripe;
    std::span<const std::pair<int, std::span<const std::byte>>> shards;
    std::span<const std::byte> output;
};

class Core {
public:
    explicit Core(const RBCConfig& config);

    std::generator<Action> on_msg(RBCMessage msg);

private:
    std::generator<Action> start_as_leader(ValPayload self_val);
    std::generator<Action> on_val(int sender, ValPayload p);
    std::generator<Action> on_echo(int sender, EchoPayload p);
    std::generator<Action> on_ready(int sender, ReadyPayload p);
    std::generator<Action> co_yield_actions(Hash root);

    [[nodiscard]] bool accept_root(const Hash& h) const;
    [[nodiscard]] bool is_valid_val(int sender, const ValPayload& p) const;
    [[nodiscard]] bool should_send_ready(const Hash& root) const;
    [[nodiscard]] bool can_decode(const Hash& root) const;
    [[nodiscard]] size_t count_echo(const Hash& root) const;
    [[nodiscard]] size_t count_ready(const Hash& root) const;

    int sid_, pid_, N_, f_, leader_;
    std::optional<Hash> current_root_;

    std::map<Hash, bool> echo_sent_for_;
    std::map<Hash, bool> ready_sent_for_;
    std::map<Hash, bool> decode_triggered_for_;

    std::map<Hash, std::map<int, std::vector<std::byte>>> stripes_;
    std::map<Hash, std::set<int>> echo_senders_;
    std::map<Hash, std::set<int>> ready_senders_;
};

} // namespace Honey::BFT::RBC
