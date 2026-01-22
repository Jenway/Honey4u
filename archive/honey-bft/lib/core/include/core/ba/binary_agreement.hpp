// core/ba/binary_agreement.hpp
#include "core/ba/ba_core.hpp"
#include "core/ba/messages.hpp"
#include "core/concepts.hpp"

namespace Honey::BFT::BA {

template <typename T>
concept CoinService = requires(T& coin, int round) {
    { coin.get_coin(round) } -> AwaitableOf<int>;
};

template <typename T>
concept Transceiver = requires(T& transceiver, Message msg) {
    { transceiver.broadcast(msg) } -> AwaitableOf<void>;
};

template <
    template <typename> typename TaskT,
    Transceiver T, CoinService Coin>
class BinaryAgreement {
private:
    const SystemContext& system_ctx_;
    int sid_ {};
    NodeId my_pid_ {}, leader_ {};
    T& transport_;
    Coin& coin_;
    BACore core_;

    /*
    - upon receiving input b_{input}, set est_0 := b_{input} and proceed as follows in consecutive epochs, with increasing labels r:

    – multicast BVAL_r(est_r)
    – bin\_values_r := {}
    – upon receiving BVAL_r(b) messages from f + 1 nodes, if BVAL_r(b) has not been sent, multicast BVAL_r(b)
    – upon receiving BVALr(b) messages from 2 f + 1 nodes,bin\_values_r := bin\_values_r ∪ {b}
    – wait until bin\_values_r  != /0, then
        - multicast AUX_r(w) where w ∈ bin\_values_r
        - wait until at least (N − f ) AUXr messages have been received, such that the set of values carried by these messages, vals are a subset of bin_valuesr (note that bin_valuesr may continue to change as BVALr messages are received, thus this condition may be triggered upon
    arrival of either an AUXr or a BVALr message)
        -  s ← Coinr.GetCoin() // See Figure 12
        - if vals = {b}, then
            - estr+1 := b
            - if (b = s%2) then output b
        - else estr+1 := s%2
    - continue looping until both a value b is output in some round r,
    and the value Coinr′ = b for some round r′ > r

    */

public:
    BinaryAgreement(
        const SystemContext& system_ctx,
        int sid,
        NodeId my_pid,
        NodeId leader,
        T& transport,
        Coin& coin)
        : system_ctx_(system_ctx)
        , sid_(sid)
        , my_pid_(my_pid)
        , leader_(leader)
        , transport_(transport)
        , coin_(coin)
        , core_({ .session_id = sid, .node_id = my_pid, .total_nodes = system_ctx.N, .fault_tolerance = system_ctx.f, .leader_id = leader })
    {
    }

    template <AsyncStreamOf<Message> Stream>
    auto run(int input_val, Stream stream) -> TaskT<int>
    {
        int r = 0;
        int estimate = input_val;
        std::optional<int> output_value = std::nullopt;

        // Algorithm: "set est_0 := input ... loop"
        core_.start_round(r, estimate);

        // Initial BVAL
        co_await broadcast_bval(r, estimate);

        while (auto msg_opt = co_await stream.next()) {
            Message msg = *msg_opt;

            if (std::holds_alternative<ValPayload>(msg.payload)) {
                auto& val_payload = std::get<ValPayload>(msg.payload);
                core_.observe_bval(val_payload.round, msg.sender, val_payload.value);
            } else if (std::holds_alternative<AuxPayload>(msg.payload)) {
                auto& aux_payload = std::get<AuxPayload>(msg.payload);
                core_.observe_aux(aux_payload.round, msg.sender, aux_payload.value);
            }
            // Action A: Multicast BVAL (Triggered by f+1 BVALs)
            for (int v : { 0, 1 }) {
                if (core_.should_multicast_bval(r, v)) {
                    co_await broadcast_bval(r, v);
                }
            }

            // Action B: Multicast AUX (Triggered by bin_values != empty)
            if (auto w = core_.should_multicast_aux(r)) {
                co_await broadcast_aux(r, *w);
            }

            // Action C: Try to finish round (Triggered by N-f AUXs && subset check)
            if (core_.is_ready_for_coin(r)) {
                // Get Coin (Async)
                int s = co_await coin_.get_coin(r);

                // Advance Round
                auto result = core_.advance_round_with_coin(r, s);

                if (result.decision && !output_value) {
                    output_value = result.decision;
                }

                // Prepare next round
                r++;
                estimate = result.next_estimate;
                core_.start_round(r, estimate);

                // Start next round logic
                co_await broadcast_bval(r, estimate);

                if (output_value)
                    co_return *output_value;
            }
        }
    }

private:
    TaskT<void> broadcast_bval(int r, int val)
    {
        core_.mark_bval_sent(r, val);
        core_.observe_bval(r, my_pid_, val);
        co_await transport_.broadcast(Message {
            .sender = my_pid_,
            .session_id = sid_,
            .payload = ValPayload { .round = r, .value = val } });
    }

    TaskT<void> broadcast_aux(int r, int val)
    {
        core_.mark_aux_sent(r);
        core_.observe_aux(r, my_pid_, val);
        co_await transport_.broadcast(Message {
            .sender = my_pid_,
            .session_id = sid_,
            .payload = AuxPayload { .round = r, .value = val } });
    }
};
} // namespace Honey::BFT::BA
