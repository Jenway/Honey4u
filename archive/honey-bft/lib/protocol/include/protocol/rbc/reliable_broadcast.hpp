#pragma once

#include "core/common.hpp"
#include "core/rbc/rbc_core.hpp"
#include "protocol/concepts.hpp"
#include "protocol/rbc/concepts.hpp"
#include <exec/async_scope.hpp>
#include <exec/task.hpp>
#include <stdexec/execution.hpp>

namespace Honey::BFT::RBC {
using Byte = std::byte;
using BytesSpan = std::span<const Byte>;
using Honey::BFT::SenderOf;

template <Transceiver T, CryptoService C>
class ReliableBroadcast {
private:
    const SystemContext& system_ctx_;
    int sid_;
    NodeId my_pid_, leader_;
    T& transport_;
    C& crypto_;
    Core core_;

    using Tree = typename C::MerkleTreeType;

public:
    ReliableBroadcast(
        const SystemContext& system_ctx,
        int sid,
        NodeId my_pid,
        NodeId leader,
        T& transport,
        C& crypto)
        : system_ctx_(system_ctx)
        , sid_(sid)
        , my_pid_(my_pid)
        , leader_(leader)
        , transport_(transport)
        , crypto_(crypto)
        , core_({ .session_id = sid, .node_id = my_pid, .total_nodes = system_ctx.N, .fault_tolerance = system_ctx.f, .leader_id = leader })
    {
    }

    template <AsyncStreamOf<RBCMessage> In>
    auto run(std::optional<std::vector<Byte>> input, In in) -> TaskOf<RBCOutput>
    {
        // If leader and has input, broadcast VAL
        if (my_pid_ == leader_ && input) {
            Tree tree = co_await crypto_.async_build_merkle_tree(
                system_ctx_.N - system_ctx_.f,
                system_ctx_.N,
                BytesSpan { *input });

            co_await broadcast_val(tree);
        }

        // Main message processing loop
        while (auto msg_opt = co_await in.next()) {
            RBCMessage msg = *msg_opt;

            // Verify merkle proof for Val and Echo messages
            if (auto* p = std::get_if<ValPayload>(&msg.payload)) {
                if (!co_await crypto_.async_verify_merkle(p->stripe, p->proof_index, p->merkle_path, p->root_hash))
                    continue;
            } else if (auto* p = std::get_if<EchoPayload>(&msg.payload)) {
                if (!co_await crypto_.async_verify_merkle(p->stripe, p->proof_index, p->merkle_path, p->root_hash))
                    continue;
            }

            // Process message through Core and handle resulting actions
            for (auto action : core_.on_msg(msg)) {
                switch (action.type) {
                case Action::Type::BroadcastEcho: {
                    auto echo_msg = construct_echo(action.root_hash, msg);
                    co_await transport_.broadcast(echo_msg);
                    break;
                }
                case Action::Type::BroadcastReady: {
                    auto ready_msg = construct_ready(action.root_hash);
                    co_await transport_.broadcast(ready_msg);
                    break;
                }
                case Action::Type::Decode: {
                    // Collect shards for decoding
                    std::vector<std::pair<int, std::vector<Byte>>> shards_vec;
                    for (const auto& [node_id, stripe_span] : action.shards) {
                        shards_vec.emplace_back(node_id, std::vector<Byte>(stripe_span.begin(), stripe_span.end()));
                    }

                    auto result = co_await crypto_.async_decode(
                        system_ctx_.N - system_ctx_.f,
                        system_ctx_.N,
                        shards_vec);

                    if (result) {
                        co_return *result;
                    }
                    break;
                }
                case Action::Type::Output:
                    // Output action contains the final result
                    co_return std::vector<Byte>(action.output.begin(), action.output.end());
                }
            }
        }

        throw std::runtime_error("RBC terminated without delivering output");
    }

private:
    RBCMessage construct_echo(const Hash& root, const RBCMessage& original_val)
    {
        // Extract the stripe from the original VAL message
        const auto& val_payload = std::get<ValPayload>(original_val.payload);
        return RBCMessage {
            .type = RBCMessage::Type::Echo,
            .sender = my_pid_,
            .session_id = sid_,
            .payload = EchoPayload {
                .root_hash = root,
                .proof_index = val_payload.proof_index,
                .merkle_path = val_payload.merkle_path,
                .stripe = val_payload.stripe }
        };
    }

    RBCMessage construct_ready(const Hash& root)
    {
        return RBCMessage {
            .type = RBCMessage::Type::Ready,
            .sender = my_pid_,
            .session_id = sid_,
            .payload = ReadyPayload {
                .root_hash = root }
        };
    }

    auto broadcast_val(Tree tree) -> TaskOf<void>
    {
        for (int i = 0; i < system_ctx_.N; ++i) {
            RBCMessage msg {
                .type = RBCMessage::Type::Val,
                .sender = my_pid_,
                .session_id = sid_,
                .payload = crypto_.extract_val_payload(tree, i)
            };
            co_await transport_.unicast(i, msg);
        }

        // Leader should also process their own VAL message
        RBCMessage leader_msg {
            .type = RBCMessage::Type::Leader,
            .sender = my_pid_,
            .session_id = sid_,
            .payload = crypto_.extract_val_payload(tree, my_pid_)
        };

        // Process leader's own message to initialize Core state
        for (auto action : core_.on_msg(leader_msg)) {
            if (action.type == Action::Type::BroadcastReady) {
                auto ready_msg = construct_ready(action.root_hash);
                co_await transport_.broadcast(ready_msg);
            }
        }
    }
};

} // namespace Honey::BFT::RBC
