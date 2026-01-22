#pragma once

#include "core/common.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <variant>
#include <vector>

namespace Honey::BFT::RBC {

constexpr std::int8_t SHA256_BYTES = 32;
using SHA256Hash = std::array<std::byte, SHA256_BYTES>;
using Hash = SHA256Hash;

struct ValPayload {
    Hash root_hash;
    size_t proof_index;
    std::vector<Hash> merkle_path;
    std::vector<std::byte> stripe;
};

struct EchoPayload {
    Hash root_hash;
    size_t proof_index;
    std::vector<Hash> merkle_path;
    std::vector<std::byte> stripe;
};

struct ReadyPayload {
    Hash root_hash;
};

using RBCPayload = std::variant<ValPayload, EchoPayload, ReadyPayload>;

struct RBCMessage {
    NodeId sender {};
    int session_id {};
    RBCPayload payload;
};

using RBCOutput = std::vector<std::byte>;

} // namespace Honey::BFT::RBC
