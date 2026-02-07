#pragma once

#include "core/common.hpp"
#include "core/prbc/prbc_core.hpp"
#include "core/rbc/messages.hpp"
#include "crypto/blst/P1.hpp"
#include "service/concepts.hpp"
#include "service/prbc/concepts.hpp"
#include "service/rbc/concepts.hpp"
#include <algorithm>
#include <array>
#include <exec/task.hpp>
#include <optional>
#include <span>
#include <stdexcept>
#include <stdexec/execution.hpp>

namespace Honey::BFT::PRBC {

using Honey::BFT::PRBC::Transceiver;
using Honey::BFT::RBC::Byte;
using Honey::BFT::RBC::BytesSpan;

struct PRBCOutput {
    std::vector<Byte> value;
    std::vector<Byte> proof; // The combined threshold signature
};

template <Transceiver T, CryptoService C>
class ProvableReliableBroadcast {
private:
    const SystemContext& system_ctx_;
    int sid_;
    NodeId my_pid_, leader_;
    T& transport_;
    C& crypto_;
    Core core_;

    using MerkleBuildResult = typename C::MerkleBuildResult;

public:
    ProvableReliableBroadcast(
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

    template <AsyncStreamOf<PRBCMessage> In>
    auto run(std::optional<std::vector<Byte>> input, In in) -> TaskOf<PRBCOutput>
    {
        // If leader and has input, broadcast VAL
        if (my_pid_ == leader_ && input) {
            MerkleBuildResult tree = co_await crypto_.async_build_merkle_tree(
                system_ctx_.N - 2 * system_ctx_.f, // K = N - 2f
                system_ctx_.N,
                BytesSpan { *input });

            co_await broadcast_val(tree);
        }

        while (auto msg_opt = co_await in.next()) {
            PRBCMessage msg = *msg_opt;

            // Verification
            bool valid = true;
            if (auto* p = std::get_if<ValPayload>(&msg.payload)) {
                valid = co_await crypto_.async_verify_merkle(p->stripe, p->proof_index, p->merkle_path, p->root_hash);
            } else if (auto* p = std::get_if<EchoPayload>(&msg.payload)) {
                valid = co_await crypto_.async_verify_merkle(p->stripe, p->proof_index, p->merkle_path, p->root_hash);
            } else if (auto* p = std::get_if<ReadyPayload>(&msg.payload)) {
                // Verify signature share
                std::vector<Byte> data_to_verify;
                append_u64(data_to_verify, static_cast<uint64_t>(sid_));
                append_hash(data_to_verify, p->root_hash);

                auto share_opt = deserialize_share(p->signature_share);
                if (!share_opt) {
                    valid = false;
                } else {
                    valid = co_await crypto_.async_verify_share(*share_opt, data_to_verify, msg.sender);
                }
            }

            if (!valid)
                continue;

            // Process via Core
            // For Ready message, we use on_signature_share for the sig part,
            // but we MUST also call on_msg for the Ready counting part?
            // PRBCCore::on_msg(Ready) handles counting.
            // PRBCCore::on_signature_share handles the share storage and completion check.
            // We should call BOTH.

            // First pass to generic handler
            for (auto action : core_.on_msg(msg)) {
                auto res = co_await handle_action(action);
                if (res)
                    co_return *res;
            }

            // If it was a Ready message, also pass signature to core
            if (auto* p = std::get_if<ReadyPayload>(&msg.payload)) {
                for (auto action : core_.on_signature_share(msg.sender, p->root_hash, p->signature_share)) {
                    auto res = co_await handle_action(action);
                    if (res)
                        co_return *res;
                }
            }
        }

        throw std::runtime_error("PRBC terminated without delivering output");
    }

private:
    auto handle_action(Action action) -> TaskOf<std::optional<PRBCOutput>>
    {
        switch (action.type) {
        case Action::Type::Broadcast: {
            // We need to reconstruct the full message because Action only carries payload
            // But wait, Action payload IS the serialized message specific to PRBC?
            // PRBCCore::serialize_payload puts the specific payload (Val/Echo/Ready) into bytes.
            // But the PRBCMessage wrapper (Type, Sender, Sid) needs to be added.
            // The Action payload from Core has: [TypeByte] + [PayloadBytes]
            // We need to parse the TypeByte to construct PRBCMessage correctly.

            // Let's look at how Core constructs it.
            // Core pushes (byte)Type then calls serialize_payload.
            if (action.payload.empty())
                co_return std::nullopt;

            auto type_byte = static_cast<uint8_t>(action.payload[0]);
            std::vector<Byte> real_payload_bytes(action.payload.begin() + 1, action.payload.end());

            PRBCMessage msg {
                .sender = my_pid_,
                .session_id = sid_
            };

            // We need to deserialize the payload bytes back to the variant?
            // Or we can just trust the Core serialized it correctly and we need to wrap it?
            // The Transceiver expects a PRBCMessage struct.
            // So we MUST deserialize or have a better way to pass the struct.
            // Since we are inside the same process, maybe Core should yield the Struct directly?
            // But we wanted generic Actions.
            // So we assume we can deserialize.

            // Simplified for now: We manually reconstruct based on Type
            // This is slightly inefficient (Serialize -> Deserialize -> Copy) but fits the architecture.

            // ... implementing deserialization here is tedious without helpers.
            // Let's cheat slightly: The Core constructs generic payloads.
            // We know what they are based on type.
            // Actually, let's fix `Action` usage in Core to pass specific structs if possible?
            // No, we committed to `std::vector<Byte>`.

            // Re-implementation of deserialization:
            // We need `deserialize_payload` helpers.
            // Since we don't have them in `messages.hpp` yet, I'll rely on the fact
            // that `PRBCMessage` is what `transport_` expects.
            // If `transport_.broadcast` takes `PRBCMessage`, I need to build one.

            if (type_byte == static_cast<uint8_t>(PRBCMessage::Type::Echo)) {
                std::span<const Byte> payload_span(real_payload_bytes);
                auto echo_opt = deserialize_echo(payload_span);
                if (!echo_opt)
                    co_return std::nullopt;

                PRBCMessage echo_msg {
                    .type = PRBCMessage::Type::Echo,
                    .sender = my_pid_,
                    .session_id = sid_,
                    .payload = std::move(*echo_opt)
                };

                co_await transport_.broadcast(echo_msg);
            } else if (type_byte == static_cast<uint8_t>(PRBCMessage::Type::Ready)) {
                std::span<const Byte> payload_span(real_payload_bytes);
                auto ready_opt = deserialize_ready(payload_span);
                if (!ready_opt)
                    co_return std::nullopt;

                PRBCMessage ready_msg {
                    .type = PRBCMessage::Type::Ready,
                    .sender = my_pid_,
                    .session_id = sid_,
                    .payload = std::move(*ready_opt)
                };

                co_await transport_.broadcast(ready_msg);
            } else if (type_byte == static_cast<uint8_t>(PRBCMessage::Type::Val)) {
                std::span<const Byte> payload_span(real_payload_bytes);
                auto val_opt = deserialize_val(payload_span);
                if (!val_opt)
                    co_return std::nullopt;

                PRBCMessage val_msg {
                    .type = PRBCMessage::Type::Val,
                    .sender = my_pid_,
                    .session_id = sid_,
                    .payload = std::move(*val_opt)
                };

                co_await transport_.broadcast(val_msg);
            }

            break;
        }
        case Action::Type::Signal: {
            if (action.tag != 1) {
                break;
            }
            // Core requests us to Sign and Broadcast Ready
            // Payload is Hash
            if (action.payload.size() != 32)
                co_return std::nullopt; // Hash size

            Hash root;
            std::copy_n(action.payload.begin(), 32, root.begin());

            // Sign
            std::vector<Byte> data_to_sign;
            append_u64(data_to_sign, static_cast<uint64_t>(sid_));
            append_hash(data_to_sign, root);
            auto sig_share = co_await crypto_.async_sign_share(data_to_sign);
            auto sig_bytes = serialize_share(sig_share);

            // Construct Ready Message
            ReadyPayload ready_p {
                .root_hash = root,
                .signature_share = std::move(sig_bytes)
            };

            PRBCMessage ready_msg {
                .type = PRBCMessage::Type::Ready,
                .sender = my_pid_,
                .session_id = sid_,
                .payload = ready_p
            };

            // Count our own share
            for (auto action2 : core_.on_signature_share(my_pid_, root, ready_p.signature_share)) {
                auto res = co_await handle_action(action2);
                if (res)
                    co_return *res;
            }

            co_await transport_.broadcast(ready_msg);
            break;
        }
        case Action::Type::Result: {
            // Core says we can output. Payload is Hash.
            Hash root;
            std::copy_n(action.payload.begin(), 32, root.begin());

            // 1. Decode
            auto shards = core_.get_shards(root);
            auto val_opt = co_await crypto_.async_decode(
                system_ctx_.N - 2 * system_ctx_.f,
                system_ctx_.N,
                shards);

            if (!val_opt)
                throw std::runtime_error("Failed to decode in Result phase");

            // 2. Combine Signatures
            auto shares = core_.get_signature_shares(root);
            auto partials = make_partials(shares);
            auto proof_opt = co_await crypto_.async_combine_signatures(std::span(partials));

            if (!proof_opt)
                throw std::runtime_error("Failed to combine signatures in Result phase");

            co_return PRBCOutput {
                .value = *val_opt,
                .proof = serialize_signature(*proof_opt)
            };
        }
        default:
            break;
        }
        co_return std::nullopt;
    }

    auto broadcast_val(MerkleBuildResult tree) -> TaskOf<void>
    {
        for (int i = 0; i < system_ctx_.N; ++i) {
            PRBCMessage msg {
                .type = PRBCMessage::Type::Val,
                .sender = my_pid_,
                .session_id = sid_,
                .payload = C::make_val_payload(tree, i)
            };
            co_await transport_.unicast(i, msg);
        }

        // Self-send to leader
        PRBCMessage leader_msg {
            .type = PRBCMessage::Type::Leader,
            .sender = my_pid_,
            .session_id = sid_,
            .payload = C::make_val_payload(tree, my_pid_)
        };
        for (auto action : core_.on_msg(leader_msg)) {
            co_await handle_action(action);
        }
    }

    static std::vector<Byte> serialize_share(const typename C::SignatureShare& share)
    {
        auto bytes = share.serialize();
        return std::vector<Byte>(bytes.begin(), bytes.end());
    }

    static std::optional<typename C::SignatureShare> deserialize_share(const std::vector<Byte>& bytes)
    {
        if (bytes.size() != Honey::Crypto::bls::P1::SERIALIZED_SIZE)
            return std::nullopt;

        std::array<Byte, Honey::Crypto::bls::P1::SERIALIZED_SIZE> buf {};
        std::copy(bytes.begin(), bytes.end(), buf.begin());
        auto share_opt = Honey::Crypto::bls::P1::deserialize(std::span<const Byte, Honey::Crypto::bls::P1::SERIALIZED_SIZE>(buf));
        if (!share_opt)
            return std::nullopt;
        return *share_opt;
    }

    static std::vector<Byte> serialize_signature(const typename C::Signature& sig)
    {
        auto bytes = sig.serialize();
        return std::vector<Byte>(bytes.begin(), bytes.end());
    }

    static std::vector<typename C::PartialSignature> make_partials(
        const std::vector<std::pair<int, std::vector<Byte>>>& shares)
    {
        std::vector<typename C::PartialSignature> partials;
        partials.reserve(shares.size());
        for (const auto& [pid, bytes] : shares) {
            auto share_opt = deserialize_share(bytes);
            if (!share_opt) {
                continue;
            }
            partials.push_back(typename C::PartialSignature { .player_id = pid, .value = *share_opt });
        }
        return partials;
    }

    // Helper to map serialized payload back to message
    // (Omitted for brevity, assuming we fix this or implement it)
    // Actually we skipped the 'Broadcast' action implementation above.
    // For PRBC, the only generic broadcasts are ECHO.
    // VAL is handled specifically.
    // READY is handled via Signal.
    // So only ECHO uses Action::Broadcast.
    // Let's implement ECHO reconstruction.
};

} // namespace Honey::BFT::PRBC
