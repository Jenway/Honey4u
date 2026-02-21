#pragma once

#include "core/ba/ba_core.hpp"
#include "core/ba/messages.hpp"
#include "core/common.hpp"
#include "protocol/concepts.hpp"
#include <exec/task.hpp>
#include <map>
#include <optional>
#include <stdexec/execution.hpp>

namespace Honey::BFT::BA {

using Honey::BFT::SenderOf;

/**
 * @brief Concept for a type that can provide coin values for a given round
 */
template <typename T>
concept CoinProvider = requires(T& cp, int round) {
    { cp.request_coin(round) } -> SenderOf<int>;
};

/**
 * @brief Concept for message broadcast
 */
template <typename T>
concept MessageBroadcaster = requires(T& broadcaster, Message msg) {
    { broadcaster.broadcast(msg) } -> SenderOf<void>;
};

template <MessageBroadcaster T, CoinProvider Coin>
class BinaryAgreement {
private:
    int sid_;
    int node_id_;
    const SystemContext& sys_ctx_;
    T& transport_;
    Coin& coin_;
    Core core_;

public:
    BinaryAgreement(
        int sid,
        int node_id,
        const SystemContext& sys_ctx,
        T& transport,
        Coin& coin)
        : sid_(sid)
        , node_id_(node_id)
        , sys_ctx_(sys_ctx)
        , transport_(transport)
        , coin_(coin)
        , core_({ .session_id = sid, .node_id = node_id, .total_nodes = sys_ctx.N, .fault_tolerance = sys_ctx.f })
    {
    }

    /**
     * @brief Background message processing task
     */
    template <AsyncStreamOf<Message> In>
    auto run(In in) -> exec::task<int>
    {
        while (auto msg_opt = co_await in.next()) {
            Message msg = *msg_opt;

            if (msg.session_id != sid_)
                continue;

            if (auto* p = std::get_if<ValPayload>(&msg.payload)) {
                for (auto action : core_.on_bval(p->round, msg.sender, p->value)) {
                    co_await handle_action(action);
                    if (outcome_)
                        co_return *outcome_;
                }
            } else if (auto* p = std::get_if<AuxPayload>(&msg.payload)) {
                for (auto action : core_.on_aux(p->round, msg.sender, p->value)) {
                    co_await handle_action(action);
                    if (outcome_)
                        co_return *outcome_;
                }
            }
        }

        if (outcome_)
            co_return *outcome_;
        throw std::runtime_error("BA terminated without decision");
    }

    /**
     * @brief Propose a value
     * @param value Binary value (0 or 1)
     */
    auto propose(int value) -> exec::task<void>
    {
        if (value != 0 && value != 1) {
            throw std::invalid_argument("Binary agreement value must be 0 or 1");
        }

        // Start round 0 with initial estimate
        for (auto action : core_.start_round(0, value)) {
            co_await handle_action(action);
        }
    }

private:
    auto handle_action(const Action& action) -> exec::task<void>
    {
        switch (action.type) {
        case Action::Type::BroadcastBval: {
            Message msg {
                .sender = node_id_,
                .session_id = sid_,
                .payload = ValPayload {
                    .round = action.round,
                    .value = action.value }
            };
            co_await transport_.broadcast(msg);
            break;
        }

        case Action::Type::BroadcastAux: {
            Message msg {
                .sender = node_id_,
                .session_id = sid_,
                .payload = AuxPayload {
                    .round = action.round,
                    .value = action.value }
            };
            co_await transport_.broadcast(msg);
            break;
        }

        case Action::Type::RequestCoin: {
            // Request coin through the injected coin provider
            int coin_value = co_await coin_.request_coin(action.round);

            // Process coin result
            for (auto next_action : core_.on_coin_result(action.round, coin_value)) {
                co_await handle_action(next_action);
            }
            break;
        }

        case Action::Type::Output:
            outcome_ = action.value;
            break;
        }
    }

    std::optional<int> outcome_;
};

} // namespace Honey::BFT::BA
