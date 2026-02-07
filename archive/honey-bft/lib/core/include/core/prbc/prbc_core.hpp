#pragma once

#include "core/prbc/messages.hpp"
#include "core/rbc/rbc_core.hpp"
#include <generator>
#include <map>
#include <optional>
#include <set>
#include <vector>

namespace Honey::BFT::PRBC {

using Honey::BFT::Action;
using Honey::BFT::RBC::EchoPayload;
using Honey::BFT::RBC::Hash;
using Honey::BFT::RBC::RBCConfig;
using Honey::BFT::RBC::ValPayload;

class Core {
public:
    explicit Core(const RBCConfig& config);

    std::generator<Action> on_msg(PRBCMessage msg);

    // Called when Service verifies a signature share from a READY message
    std::generator<Action> on_signature_share(int sender, const Hash& root, std::vector<std::byte> share);

    // Helper to get decoding shards
    [[nodiscard]] std::vector<std::pair<int, std::vector<std::byte>>> get_shards(const Hash& root) const;

    // Helper to get signature shares for combination
    [[nodiscard]] std::vector<std::pair<int, std::vector<std::byte>>> get_signature_shares(const Hash& root) const;

private:
    std::generator<Action> start_as_leader(ValPayload self_val);
    std::generator<Action> on_val(int sender, ValPayload p);
    std::generator<Action> on_echo(int sender, EchoPayload p);
    std::generator<Action> on_ready(int sender, ReadyPayload p);
    std::generator<Action> check_completion(const Hash& root);
    std::generator<Action> try_send_ready(const Hash& root);

    [[nodiscard]] bool accept_root(const Hash& h) const;
    [[nodiscard]] bool is_valid_val(int sender, const ValPayload& p) const;
    [[nodiscard]] bool can_decode(const Hash& root) const;
    [[nodiscard]] size_t count_echo(const Hash& root) const;
    [[nodiscard]] size_t count_ready(const Hash& root) const;

    int sid_, pid_, N_, f_, leader_;
    std::optional<Hash> current_root_;

    std::map<Hash, bool> echo_sent_for_;
    std::map<Hash, bool> ready_sent_for_;
    std::map<Hash, bool> output_produced_;

    std::map<Hash, std::map<int, std::vector<std::byte>>> stripes_;
    std::map<Hash, std::set<int>> echo_senders_;
    std::map<Hash, std::set<int>> ready_senders_;

    // PRBC specific
    std::map<Hash, std::map<int, std::vector<std::byte>>> signature_shares_;
};

} // namespace Honey::BFT::PRBC
