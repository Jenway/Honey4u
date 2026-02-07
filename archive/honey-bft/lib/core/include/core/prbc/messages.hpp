#pragma once
#include "core/rbc/messages.hpp"
#include <optional>
#include <span>
#include <vector>

#include <algorithm> // For copy_n
#include <cstring> // For memcpy

namespace Honey::BFT::PRBC {

using Honey::BFT::NodeId;
using Honey::BFT::RBC::EchoPayload;
using Honey::BFT::RBC::Hash;
using Honey::BFT::RBC::ValPayload;

struct ReadyPayload {
    Hash root_hash;
    std::vector<std::byte> signature_share;
};

using PRBCPayload = std::variant<ValPayload, EchoPayload, ReadyPayload>;

struct PRBCMessage {
    enum class Type : uint8_t {
        Leader,
        Val,
        Echo,
        Ready
    } type;
    NodeId sender {};
    int session_id {};
    PRBCPayload payload;
};

// Re-export RBC helper for Hash
using Honey::BFT::RBC::append_bytes;
using Honey::BFT::RBC::append_hash;
using Honey::BFT::RBC::append_u64;

inline void serialize_payload(const ReadyPayload& p, std::vector<std::byte>& buf)
{
    append_hash(buf, p.root_hash);
    append_u64(buf, p.signature_share.size());
    append_bytes(buf, p.signature_share);
}

// Deserialization helpers
inline bool read_bytes(std::span<const std::byte>& data, size_t n, std::vector<std::byte>& out)
{
    if (data.size() < n)
        return false;
    out.assign(data.begin(), data.begin() + n);
    data = data.subspan(n);
    return true;
}

inline bool read_hash(std::span<const std::byte>& data, Hash& out)
{
    if (data.size() < 32)
        return false;
    std::copy_n(data.begin(), 32, out.begin());
    data = data.subspan(32);
    return true;
}

inline bool read_u64(std::span<const std::byte>& data, uint64_t& out)
{
    if (data.size() < 8)
        return false;
    std::memcpy(&out, data.data(), 8);
    data = data.subspan(8);
    return true;
}

inline std::optional<EchoPayload> deserialize_echo(std::span<const std::byte> data)
{
    EchoPayload p;
    if (!read_hash(data, p.root_hash))
        return std::nullopt;
    if (!read_u64(data, p.proof_index))
        return std::nullopt;

    uint64_t path_size;
    if (!read_u64(data, path_size))
        return std::nullopt;
    p.merkle_path.resize(path_size);
    for (size_t i = 0; i < path_size; ++i) {
        if (!read_hash(data, p.merkle_path[i]))
            return std::nullopt;
    }

    uint64_t stripe_size;
    if (!read_u64(data, stripe_size))
        return std::nullopt;
    if (!read_bytes(data, stripe_size, p.stripe))
        return std::nullopt;

    return p;
}

inline std::optional<ValPayload> deserialize_val(std::span<const std::byte> data)
{
    ValPayload p;
    if (!read_hash(data, p.root_hash))
        return std::nullopt;
    if (!read_u64(data, p.proof_index))
        return std::nullopt;

    uint64_t path_size;
    if (!read_u64(data, path_size))
        return std::nullopt;
    p.merkle_path.resize(path_size);
    for (size_t i = 0; i < path_size; ++i) {
        if (!read_hash(data, p.merkle_path[i]))
            return std::nullopt;
    }

    uint64_t stripe_size;
    if (!read_u64(data, stripe_size))
        return std::nullopt;
    if (!read_bytes(data, stripe_size, p.stripe))
        return std::nullopt;

    return p;
}

inline std::optional<ReadyPayload> deserialize_ready(std::span<const std::byte> data)
{
    ReadyPayload p;
    if (!read_hash(data, p.root_hash))
        return std::nullopt;
    uint64_t sig_size;
    if (!read_u64(data, sig_size))
        return std::nullopt;
    if (!read_bytes(data, sig_size, p.signature_share))
        return std::nullopt;
    return p;
}

} // namespace Honey::BFT::PRBC
