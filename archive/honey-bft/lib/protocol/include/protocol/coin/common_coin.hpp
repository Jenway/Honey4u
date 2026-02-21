#pragma once

#include "core/coin/coin_core.hpp"
#include "core/coin/messages.hpp"
#include "core/common.hpp"
#include "protocol/coin/concepts.hpp"
#include "protocol/concepts.hpp"
#include <exec/task.hpp>
#include <map>
#include <stdexec/execution.hpp>
#include <vector>

namespace Honey::BFT::Coin {

using Honey::BFT::SenderOf;
using Byte = std::byte;

template <Transceiver T, CryptoService C>
class CommonCoin {
private:
    struct RoundResult {
        bool completed = false;
        uint8_t value = 0;
        std::vector<std::coroutine_handle<>> waiters;
    };

    struct RoundResultAwaiter {
        RoundResult* result;

        explicit RoundResultAwaiter(RoundResult& r)
            : result(&r)
        {
        }

        [[nodiscard]] bool await_ready() const noexcept { return result->completed; }

        bool await_suspend(std::coroutine_handle<> h) noexcept
        {
            if (result->completed)
                return false;
            result->waiters.push_back(h);
            return true;
        }

        [[nodiscard]] uint8_t await_resume() const noexcept { return result->value; }
    };

public:
    CommonCoin(
        const SystemContext& sys_ctx,
        int sid,
        int pid,
        T& transport,
        C& crypto_svc)
        : sys_ctx_(sys_ctx)
        , transport_(transport)
        , crypto_svc_(crypto_svc)
        , core_({ .session_id = sid, .node_id = pid, .total_nodes = sys_ctx.N, .fault_tolerance = sys_ctx.f })
    {
    }

    /**
     * @brief Background task that processes incoming messages
     */
    template <AsyncStreamOf<Message> In>
    auto run(In in) -> exec::task<void>
    {
        while (auto msg_opt = co_await in.next()) {
            Message msg = *msg_opt;

            if (msg.session_id != core_.session_id())
                continue;
            if (core_.is_finished(msg.payload.round))
                continue;

            // 1. Verify Signature Share
            auto payload_bytes = core_.make_payload_bytes(msg.payload.round);
            bool valid = co_await crypto_svc_.async_verify_share(
                msg.payload.sig, payload_bytes, msg.sender);

            if (!valid) {
                continue;
            }

            // 2. Process through Core and handle actions
            for (auto action : core_.on_share(msg.payload.round, msg.sender, msg.payload.sig)) {
                co_await handle_action(action);
            }
        }
    }

    auto get_coin(int round) -> exec::task<int>
    {
        // Fast path: already completed
        if (core_.is_finished(round)) {
            co_return static_cast<int>(core_.get_output(round));
        }

        RoundResult& result = results_[round];
        if (result.completed) {
            co_return static_cast<int>(result.value);
        }

        // Sign and broadcast our share
        auto payload_bytes = core_.make_payload_bytes(round);
        auto our_share = co_await crypto_svc_.async_sign_share(payload_bytes);

        // Process request through Core
        for (auto action : core_.request_coin(round, our_share)) {
            co_await handle_action(action);
        }

        // Wait for result if not yet completed
        if (!result.completed) {
            co_await RoundResultAwaiter(result);
        }

        co_return static_cast<int>(result.value);
    }

    void prune(int min_active_round)
    {
        std::erase_if(results_, [&](const auto& item) {
            auto const& [round, _] = item;
            return round < min_active_round;
        });
    }

private:
    auto handle_action(const Action& action) -> exec::task<void>
    {
        switch (action.type) {
        case Action::Type::BroadcastShare: {
            Message msg {
                .sender = core_.node_id(),
                .session_id = core_.session_id(),
                .payload = {
                    .round = action.round,
                    .sig = action.my_share }
            };
            co_await transport_.broadcast(msg);
            break;
        }

        case Action::Type::CombineSignatures: {
            // Convert span to vector for async operation
            std::vector<PartialSignature> shares(
                action.shares_to_combine.begin(),
                action.shares_to_combine.end());

            auto payload_bytes = core_.make_payload_bytes(action.round);

            // Combine signatures
            auto combined_opt = co_await crypto_svc_.async_combine_signatures(shares);
            if (!combined_opt) {
                co_return;
            }

            // Verify combined signature
            bool valid = co_await crypto_svc_.async_verify_signature(
                *combined_opt, payload_bytes);
            if (!valid) {
                co_return;
            }

            // Hash to bit
            uint8_t bit = crypto_svc_.hash_to_bit(*combined_opt);

            // Mark finished in core
            core_.mark_finished(action.round, bit);

            // Update result and wake waiters
            RoundResult& result = results_[action.round];
            result.completed = true;
            result.value = bit;

            auto waiters = std::move(result.waiters);
            result.waiters.clear();

            for (auto h : waiters) {
                if (h && !h.done())
                    h.resume();
            }
            break;
        }

        case Action::Type::Output:
            // Output is handled by the result awaiter mechanism
            break;
        }
    }

    const SystemContext& sys_ctx_;
    T& transport_;
    C& crypto_svc_;
    Core core_;
    std::map<int, RoundResult> results_;
};

} // namespace Honey::BFT::Coin
