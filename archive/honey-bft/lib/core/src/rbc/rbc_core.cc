#include "core/rbc/rbc_core.hpp"

namespace Honey::BFT::RBC {

RBCCore::RBCCore(const RBCConfig& config)
    : sid_(config.session_id)
    , pid_(config.node_id)
    , N_(config.total_nodes)
    , f_(config.fault_tolerance)
    , leader_(config.leader_id)
    , K_(N_ - (2 * f_))
    , EchoThreshold_(N_ - f_)
    , ReadyThreshold_(f_ + 1)
    , OutputThreshold_((2 * f_) + 1)
{
}

std::generator<Effect> RBCCore::handle_message(RBCMessage msg)
{
    // TODO: filter policy: if leader, discard all messages until sending VAL

    if (msg.session_id != sid_) {
        co_return;
    }
    if (auto* p = std::get_if<ValPayload>(&msg.payload)) {
        for (auto&& effect : handle_val(msg.sender, *p)) {
            co_yield effect;
        }
    } else if (auto* p = std::get_if<EchoPayload>(&msg.payload)) {
        for (auto&& effect : handle_echo(msg.sender, *p)) {
            co_yield effect;
        }
    } else if (auto* p = std::get_if<ReadyPayload>(&msg.payload)) {
        for (auto&& effect : handle_ready(msg.sender, *p)) {
            co_yield effect;
        }
    }
}

const std::map<NodeId, std::vector<Byte>>& RBCCore::get_shards_for_root(const Hash& root) const
{
    return stripes_.at(root);
}

/*
-   Upon receiving `VAL(h, b_i, s_i)` from P_{Sender}:
-   Multicast `ECHO(h, b_i, s_i)`.
*/
std::generator<Effect> RBCCore::handle_val(int sender, ValPayload p)
{
    if (sender != leader_ || from_leader_hash_) {
        co_return;
    }
    from_leader_hash_ = p.root_hash;

    const auto& root = p.root_hash;
    stripes_[root][pid_] = p.stripe;
    echo_senders_[root].insert(pid_);

    EchoPayload echo { .root_hash = root, .proof = p.proof, .stripe = p.stripe };
    co_yield Effect {
        .type = Effect::Type::Broadcast,
        .msg = RBCMessage { .sender = pid_, .session_id = sid_, .payload = echo }
    };
}
/*
-   Upon receiving `ECHO(h, b_j, s_j)` from party $P_j$
-   Check that $b_j$ is a valid Merkle branch for root $h$ and leaf $s_j$, and otherwise discard.
-   Upon receiving valid `ECHO(h, \cdot, \cdot)` messages from $N-f$ distinct parties:

1.  Interpolate $\{s'_j\}$ from any $N-2f$ leaves received.
2.  Recompute Merkle root $h'$ and if $h' \neq h$ then abort.
3.  If `READY(h)` has not yet been sent, multicast `READY(h)`.
*/
std::generator<Effect> RBCCore::handle_echo(int sender, EchoPayload p)
{
    const auto& root = p.root_hash;
    if (echo_senders_[root].contains(sender)) {
        co_return; // Duplicate ECHO
    }

    stripes_[root][sender] = std::move(p.stripe);
    echo_senders_[root].insert(sender);

    if (echo_senders_[root].size() >= static_cast<size_t>(EchoThreshold_) && !ready_sent_[root]) {
        ready_sent_[root] = true;
        ready_senders_[root].insert(pid_);
        ReadyPayload ready { root };
        co_yield Effect {
            .type = Effect::Type::Broadcast,
            .msg = RBCMessage { .sender = pid_, .session_id = sid_, .payload = ready }
        };
    }

    for (const auto& effect : check_delivery(root)) {
        co_yield effect;
    }
}

/*
- Upon receiving $f+1$ matching `READY(h)` messages:**
    -   If `READY(h)` has not yet been sent, multicast `READY(h)`.
- Upon receiving $2f+1$ matching `READY(h)` messages:**
    -   Wait for $N-2f$ `ECHO` messages, then decode $v$.
*/

std::generator<Effect> RBCCore::handle_ready(int sender, ReadyPayload p)
{
    const auto& root = p.root_hash;
    if (ready_senders_[root].contains(sender)) {
        co_return;
    }
    ready_senders_[root].insert(sender);

    if (ready_senders_[root].size() >= static_cast<size_t>(ReadyThreshold_) && !ready_sent_[root]) {
        ready_sent_[root] = true;
        ready_senders_[root].insert(pid_);
        ReadyPayload ready { root };
        co_yield Effect {
            .type = Effect::Type::Broadcast,
            .msg = RBCMessage { .sender = pid_, .session_id = sid_, .payload = ready }
        };
    }

    for (const auto& effect : check_delivery(root)) {
        co_yield effect;
    }
}

std::generator<Effect> RBCCore::check_delivery(Hash root)
{
    if (delivered_.contains(root) && delivered_.at(root)) {
        co_return;
    }

    // Condition 1: Received 2f+1 READYs
    if (!ready_senders_.contains(root) || ready_senders_.at(root).size() < static_cast<size_t>(OutputThreshold_)) {
        co_return;
    }

    // Condition 2: Received K valid shards (Echo messages)
    if (!stripes_.contains(root) || stripes_.at(root).size() < static_cast<size_t>(K_)) {
        co_return;
    }

    delivered_[root] = true;
    co_yield Effect { .type = Effect::Type::Deliver, .root_hash = root };
}

} // namespace Honey::BFT::RBC
