#pragma once

#include "crypto/types.hpp"
#include <array>
#include <cstddef>
#include <span>
#include <vector>

namespace Honey::Crypto::MerkleTree {

constexpr std::int8_t SHA256_BYTES = 32;
using SHA256Hash = std::array<std::byte, SHA256_BYTES>;
using Hash = SHA256Hash;

struct Proof {
    size_t leaf_index;
    std::vector<Hash> siblings;
};

struct TreeData {
    Hash root;
    std::vector<Proof> proofs;
};

[[nodiscard]]
TreeData build_and_prove(std::span<const std::vector<Byte>> leaves);

[[nodiscard]]
bool verify(BytesSpan leaf, const Proof& proof, const Hash& root) noexcept;

} // namespace Honey::Crypto::MerkleTree
