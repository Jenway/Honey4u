#pragma once

#include "core/common.hpp"
#include "core/concepts.hpp"
#include "core/rbc/concept.hpp"
#include "core/rbc/messages.hpp"
#include "core/rbc/rbc_core.hpp"
#include <stdexcept>
#include <variant>

namespace Honey::BFT::RBC {
using Honey::Crypto::MerkleTree::Tree;

template <Transceiver T, CryptoService C>
class ReliableBroadcast {
public:
    ReliableBroadcast(
        const SystemContext& system_ctx,
        int sid,
        NodeId my_pid,
        NodeId leader,
        T& transport,
        C& crypto_svc)
        : system_ctx_(system_ctx)
        , sid_(sid)
        , my_pid_(my_pid)
        , leader_(leader)
        , transport_(transport)
        , crypto_svc_(crypto_svc)
        , core_({ .session_id = sid, .node_id = my_pid, .total_nodes = system_ctx.N, .fault_tolerance = system_ctx.f, .leader_id = leader })
    {
    }

    template <template <typename> typename TaskT, AsyncStreamOf<RBCMessage> Stream>
    auto run(
        std::optional<std::vector<Byte>> input_data,
        Stream message_stream) -> TaskT<RBCOutput>
    {
        if (input_data && my_pid_ == leader_) {
            if (auto output = co_await leader_propose<TaskT>(std::move(*input_data))) {
                co_return *output;
            }
        }

        while (auto msg_opt = co_await message_stream.next()) {
            RBCMessage msg = std::move(*msg_opt);

            if (!co_await is_message_valid<TaskT>(msg)) {
                continue;
            }

            auto effects = core_.handle_message(std::move(msg));

            for (const auto& eff : effects) {
                if (auto output = co_await apply_effect<TaskT>(eff)) {
                    co_return *output;
                }
            }
        }

        throw std::runtime_error("Message stream ended before RBC could complete.");
    }

private:
    template <template <typename> typename TaskT>
    auto leader_propose(std::vector<Byte> data) -> TaskT<std::optional<RBCOutput>>
    {
        const int K = system_ctx_.N - (2 * system_ctx_.f);
        Tree tree = co_await crypto_svc_.async_build_merkle_tree(K, system_ctx_.N, data);

        auto root = tree.root();
        for (int i = 0; i < system_ctx_.N; ++i) {
            auto proof = tree.prove(i);
            if (!proof) {
                throw std::runtime_error("Failed to generate Merkle proof");
            }

            RBCMessage msg {
                .sender = my_pid_,
                .session_id = sid_,
                .payload = ValPayload {
                    .root_hash = root,
                    .proof = std::move(*proof),
                    .stripe = tree.leaf(i) }
            };
            if (i == my_pid_) {
                for (auto eff : core_.handle_message(msg)) {
                    if (auto output = co_await apply_effect<TaskT>(eff)) {
                        co_return *output;
                    }
                }
            }

            co_await transport_.unicast(i, msg);
        }
        co_return std::nullopt;
    }

    template <template <typename> typename TaskT>
    auto is_message_valid(RBCMessage msg) -> TaskT<bool>
    {
        if (const auto* p = std::get_if<ValPayload>(&msg.payload)) {
            co_return co_await crypto_svc_.async_verify_merkle(p->stripe, p->proof, p->root_hash);
        }
        if (const auto* p = std::get_if<EchoPayload>(&msg.payload)) {
            co_return co_await crypto_svc_.async_verify_merkle(p->stripe, p->proof, p->root_hash);
        }
        co_return true;
    }

    template <template <typename> typename TaskT>
    auto apply_effect(Effect eff) -> TaskT<std::optional<RBCOutput>>
    {
        switch (eff.type) {
        case Effect::Type::Broadcast:
            co_await transport_.broadcast(*eff.msg);
            break;
        case Effect::Type::SendTo:
            co_await transport_.unicast(eff.target_pid, *eff.msg);
            break;
        case Effect::Type::Deliver: {
            const auto& root = *eff.root_hash;
            const auto& shards = core_.get_shards_for_root(root);
            const int K = system_ctx_.N - (2 * system_ctx_.f);
            auto decoded = co_await crypto_svc_.async_decode(K, system_ctx_.N, shards);
            if (!decoded) {
                throw std::runtime_error(decoded.error().message());
            }
            co_return RBCOutput { .root_hash = root, .shards = shards };
        }
        }
        co_return std::nullopt;
    }

    const SystemContext& system_ctx_;
    int sid_;
    NodeId my_pid_, leader_;
    T& transport_;
    C& crypto_svc_;
    RBCCore core_;
};

} // namespace Honey::BFT::RBC
