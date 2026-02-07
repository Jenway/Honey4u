#pragma once

#include "core/common.hpp"
#include "service/broadcast/late_message_cache.hpp"
#include "service/concepts.hpp"
#include <exec/task.hpp>
#include <optional>
#include <stdexcept>
#include <stdexec/execution.hpp>
#include <vector>

namespace Honey::BFT {

using Byte = std::byte;
using BytesSpan = std::span<const Byte>;

// Concept for the Core state machine
template <typename T>
concept BroadcastCore = requires(T& core, const std::vector<Byte>& payload) {
    // Must accept generic Action-based messages
    // Note: The actual message type passed to on_msg depends on the protocol,
    // but here we assume a generic wrapper or that the Core parses the payload.
    // For now, we'll align with the existing RBC interface which takes a struct.
    // To make this truly generic, we might need a wrapper around the message.

    // Core must expose configuration for initialization
    // This is tricky for a generic template. We assume the Core is constructed outside or
    // we use a factory. For this class, we assume Core is passed in or constructed with specific config.

    typename T::Message; // The message type expected by the core

    { core.on_msg(std::declval<typename T::Message>()) } -> std::same_as<std::generator<Action>>;
};

template <
    typename CoreType,
    Transceiver T,
    CryptoService C,
    LateMessageCache Cache = NoOpLateMessageCache>
class BroadcastService {
private:
    const SystemContext& system_ctx_;
    int sid_;
    int my_pid_;
    int leader_;
    T& transport_;
    C& crypto_;
    Cache& cache_;
    CoreType core_;

    using MessageType = typename CoreType::Message;

public:
    BroadcastService(
        const SystemContext& system_ctx,
        int sid,
        int my_pid,
        int leader,
        T& transport,
        C& crypto,
        Cache& cache,
        CoreType&& core)
        : system_ctx_(system_ctx)
        , sid_(sid)
        , my_pid_(my_pid)
        , leader_(leader)
        , transport_(transport)
        , crypto_(crypto)
        , cache_(cache)
        , core_(std::move(core))
    {
    }

    template <AsyncStreamOf<MessageType> In>
    auto run(std::optional<std::vector<Byte>> input, In in) -> TaskOf<std::vector<Byte>>
    {
        // 1. Start logic (e.g. if leader)
        // Core layer should expose a way to start.
        // Existing RBCCore has start_as_leader inside on_msg(LeaderMsg) or separate?
        // In RBCCore, it's start_as_leader called when we receive Leader input or manually.
        // Let's assume we trigger it manually if we have input.

        if (my_pid_ == leader_ && input) {
            // This part is protocol specific (building merkle tree vs just signing).
            // We need a strategy or the Core needs to tell us what to do with input.
            // For generic broadcast, this is the hardest part to unify.
            // Option: Delegate "prepare_input" to a helper or Core?
            // Core is pure, so it can't do crypto.

            // For now, we will specialize or use a callback/strategy.
            // Or we assume CoreType has a helper 'prepare_initial_actions' that might return a needed Crypto task?
            // Actually, existing RBC Service does logic: Build Tree -> Unicast VAL.
            // PRBC will do: Sign -> Broadcast VAL.

            // Let's define a "InputStrategy" on the Core or use a trait.
            // Or simpler: virtual method on a Strategy class passed in?

            // Temporary pragmatic approach:
            // We can keep specific logic here via `if constexpr` or specialized traits
            // based on CoreType.

            co_await prepare_and_start(*input);
        }

        // 2. Event Loop
        while (auto msg_opt = co_await in.next()) {
            MessageType msg = *msg_opt;

            // Optional: Check cache first if this is a restart (not implemented yet)

            // Crypto Verification Hook
            if (!co_await verify_message(msg)) {
                continue;
            }

            // Core State Machine
            bool terminated = false;
            std::vector<Byte> result;

            for (auto action : core_.on_msg(msg)) {
                switch (action.type) {
                case Action::Type::Broadcast:
                    co_await transport_.broadcast(construct_msg(action.payload));
                    break;
                case Action::Type::Unicast:
                    co_await transport_.unicast(action.target, construct_msg(action.payload));
                    break;
                case Action::Type::Signal:
                    // e.g. Ready to decode
                    if (auto decoded = co_await handle_signal(action)) {
                        // Signal might return the final output directly
                        // or we feed it back to core?
                        // Existing RBC: Decode -> Core.on_decode_result?
                        // No, existing RBC service calls decode then returns.
                        // Let's allow handle_signal to return generic result.
                        // But if it's "Decode", we might need to feed result back to Core?
                        // In RBC Service: Decode -> returns result immediately.
                        result = *decoded;
                        terminated = true;
                    }
                    break;
                case Action::Type::Result:
                    result = action.payload;
                    terminated = true;
                    break;
                }
            }

            if (terminated) {
                // Cache the proof/completion
                // For RBC, "proof" is implicitly the ability to reconstruct (not strictly true for simple RBC)
                // For PRBC, it's the signature set.
                // We'll pass the result or a specific proof artifact to cache.
                cache_.add_completed_instance(sid_, result);
                co_return result;
            }
        }

        throw std::runtime_error("Broadcast terminated without output");
    }

protected:
    // These need to be implemented/specialized for RBC vs PRBC
    auto prepare_and_start(const std::vector<Byte>& input) -> TaskOf<void>;
    auto verify_message(const MessageType& msg) -> TaskOf<bool>;
    MessageType construct_msg(const std::vector<Byte>& payload);
    auto handle_signal(const Action& action) -> TaskOf<std::optional<std::vector<Byte>>>;
};

} // namespace Honey::BFT
