#pragma once

#include "core/common.hpp"
#include "core/concepts.hpp"
#include "core/rbc/concept.hpp"
#include "core/rbc/messages.hpp"
#include "core/rbc/rbc_core.hpp"
#include <variant>

namespace Honey::BFT::RBC {

template <Transceiver T, CryptoService C>
class ReliableBroadcast {
private:
    const SystemContext& system_ctx_;
    int sid_;
    NodeId my_pid_, leader_;
    T& transport_;
    C& crypto_;
    RBCCore core_;

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

    template <template <typename> typename TaskT, AsyncStreamOf<RBCMessage> Stream>
    auto run(std::optional<std::vector<Byte>> input, Stream stream) -> TaskT<RBCOutput>
    {
        if (core_.is_leader(my_pid_) && input) {
            Tree tree = co_await crypto_.async_build_merkle_tree(
                system_ctx_.N - system_ctx_.f,
                system_ctx_.N,
                BytesSpan { *input });
            co_await broadcast_val<TaskT>(tree);
        }

        while (auto msg_opt = co_await stream.next()) {
            RBCMessage msg = *msg_opt;

            // --- Step A: 验证与更新 Core (Logic) ---
            if (auto* p = std::get_if<ValPayload>(&msg.payload)) {
                if (!co_await crypto_.async_verify_merkle(p->stripe, p->proof_index, p->merkle_path, p->root_hash))
                    continue;

                if (!core_.is_valid_val(msg.sender, *p))
                    continue;

                core_.observe_val(msg.sender, *p);
            } else if (auto* p = std::get_if<EchoPayload>(&msg.payload)) {
                if (!co_await crypto_.async_verify_merkle(p->stripe, p->proof_index, p->merkle_path, p->root_hash))
                    continue;
                core_.observe_echo(msg.sender, *p);
            } else if (auto* p = std::get_if<ReadyPayload>(&msg.payload)) {
                core_.observe_ready(msg.sender, *p);
            }

            // --- Step B: 基于 Core 的状态决定副作用 (Flow Control) ---

            // 规则 1: 收到 VAL 后，如果没有发送过 ECHO，则广播 ECHO
            if (core_.has_received_val() && !core_.has_sent_echo()) {
                auto echo_msg = construct_echo(core_.get_current_root());
                co_await transport_.broadcast(echo_msg);
                core_.mark_echo_sent(); // 通知 Core 更新状态
            }

            // 规则 2: 满足阈值后，广播 READY
            if (!core_.has_sent_ready() && core_.should_send_ready()) {
                auto ready_msg = construct_ready(core_.get_current_root());
                co_await transport_.broadcast(ready_msg);
                core_.mark_ready_sent(); // 通知 Core 更新状态
            }

            if (core_.can_output()) {
                auto shards = core_.get_shards();
                auto result = co_await crypto_.async_decode(
                    system_ctx_.N - system_ctx_.f,
                    system_ctx_.N,
                    shards);
                co_return *result;
            }
        }

        // co_return std::vector<Byte> {};
        // Or should we throw an exception here?
        throw std::runtime_error("RBC terminated without delivering output");
    }

private:
    RBCMessage construct_echo(const Hash& root)
    {
        auto stripes = core_.get_shards();
        return RBCMessage {
            .sender = my_pid_,
            .session_id = sid_,
            .payload = EchoPayload {
                .root_hash = root,
                .stripe = stripes.at(my_pid_) }
        };
    }
    RBCMessage construct_ready(const Hash& root)
    {
        return RBCMessage {
            .sender = my_pid_,
            .session_id = sid_,
            .payload = ReadyPayload {
                .root_hash = root }
        };
    }
    template <template <typename> typename TaskT>
    auto broadcast_val(Tree tree) -> TaskT<void>
    {
        for (int i = 0; i < system_ctx_.N; ++i) {
            RBCMessage msg {
                .sender = my_pid_,
                .session_id = sid_,
                .payload = std::move(crypto_.extract_val_payload(tree, i))
            };
            co_await transport_.unicast(i, msg);
        }
    }
};

} // namespace Honey::BFT::RBC
