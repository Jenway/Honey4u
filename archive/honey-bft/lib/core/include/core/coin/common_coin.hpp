#pragma once

#include "core/coin/coin_core.hpp"
#include "core/coin/concept.hpp"
#include "core/coin/messages.hpp"
#include "core/concepts.hpp"
#include <algorithm>
#include <coroutine>
#include <cstdint>
#include <map>
#include <vector>

namespace Honey::BFT::Coin {

template <typename T>
concept CoinTransceiver = requires(T& t, Message msg) {
    { t.broadcast(msg) } -> AwaitableOf<void>;
};

template <
    CoinTransceiver Transport,
    CryptoService CryptoSvc,
    template <typename> typename TaskT>
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
        int sid,
        int pid,
        int N,
        int f,
        Transport transport,
        CryptoSvc crypto_svc)
        : transport_(std::move(transport))
        , crypto_svc_(std::move(crypto_svc))
        , core_(sid, pid, N, f)
    {
    }

    /**
     * @brief Background task that processes incoming messages
     */
    template <AsyncStreamOf<Message> Stream>
    TaskT<void> run(Stream message_stream)
    {
        while (auto msg_opt = co_await message_stream.next()) {
            Message msg = *msg_opt;

            if (msg.session_id != core_.session_id())
                continue;
            if (core_.is_finished(msg.payload.round))
                continue;

            // 1. Verify Signature Share
            auto payload_bytes = core_.make_payload_bytes(msg.payload.round);
            if (bool valid = co_await crypto_svc_.async_verify_share(
                    msg.payload.sig, payload_bytes, msg.sender);
                !valid) {
                // TODO: 可以在这里 log 一个警告，甚至是惩罚恶意节点
                continue;
            }

            // 2. Add to core state
            bool threshold_met = core_.add_share(
                msg.payload.round, msg.sender, msg.payload.sig);

            // 3. Try combine
            // double-check is_finished because concurrent get_coin might have finished it
            if (threshold_met && !core_.is_finished(msg.payload.round)) {
                // 这里选择 co_await 意味着消息处理会被合成操作阻塞
                // 如果合成很慢，会阻塞后续消息。但在简单模型中这是安全的。
                co_await process_threshold_met(msg.payload.round);
            }
        }
    }

    TaskT<uint8_t> get_coin(int round)
    {
        // 懒加载创建 result 条目
        RoundResult& result = results_[round];

        // Fast path
        if (result.completed) {
            co_return result.value;
        }

        // Request if not already done
        if (!core_.has_requested(round)) {
            core_.mark_requested(round);

            // 1. Sign our share
            auto payload_bytes = core_.make_payload_bytes(round);
            auto our_share = co_await crypto_svc_.async_sign_share(payload_bytes);

            // 2. Add our own share locally
            bool threshold_met = core_.add_share(round, core_.node_id(), our_share);

            // 3. Broadcast
            Message msg {
                .sender = core_.node_id(),
                .session_id = core_.session_id(),
                .payload = { .round = round, .sig = our_share }
            };
            // 并行优化：广播和本地处理可以并发，但要注意生命周期
            // 这里为了安全顺序执行
            co_await transport_.broadcast(msg);

            // 4. Check threshold
            if (threshold_met && !core_.is_finished(round)) {
                co_await process_threshold_met(round);
            }
        }

        // Wait for result
        co_await RoundResultAwaiter(result);
        co_return result.value;
    }

    void prune(int min_active_round)
    {
        std::erase_if(results_, [&](const auto& item) {
            auto const& [round, _] = item;
            return round < min_active_round;
        });
    }

private:
    TaskT<void> process_threshold_met(int round)
    {
        // Guard again inside the task to prevent double processing
        if (core_.is_finished(round))
            co_return;

        // 获取 Span，避免拷贝
        auto shares = core_.get_shares(round);
        auto payload_bytes = core_.make_payload_bytes(round);

        // Combine
        auto combined_opt = co_await crypto_svc_.async_combine_signatures(shares);
        if (!combined_opt) {
            // 这种情况理论上不该发生，除非有拜占庭节点发送了无效 share 却通过了 verify_share
            // 或者 share 数量不够。
            co_return;
        }

        // Verify Combined
        bool valid = co_await crypto_svc_.async_verify_signature(
            *combined_opt, payload_bytes);
        if (!valid) {
            co_return;
        }

        uint8_t bit = crypto_svc_.hash_to_bit(*combined_opt);

        // Mark finished
        core_.mark_finished(round);

        RoundResult& result = results_[round];
        result.completed = true;
        result.value = bit;

        // Wake waiters
        auto waiters = std::move(result.waiters);
        result.waiters.clear();

        for (auto h : waiters) {
            if (h && !h.done())
                h.resume();
        }
    }

    Transport transport_;
    CryptoSvc crypto_svc_;
    Core core_;
    std::map<int, RoundResult> results_;
};

} // namespace Honey::BFT::Coin
