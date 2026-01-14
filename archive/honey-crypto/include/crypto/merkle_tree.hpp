#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span> // C++20
#include <vector>

namespace Honey::Crypto {

using Hash = std::array<uint8_t, 32>;

namespace MerkleTree {

    struct Tree {
        size_t leaf_count;
        size_t padded_leaf_count;
        std::vector<Hash> nodes;
    };

    struct Proof {
        size_t index;
        std::vector<Hash> siblings;
    };

    Tree build(std::span<const std::vector<uint8_t>> leaves);

    std::optional<Hash> root(const Tree& tree);

    Proof prove(const Tree& tree, size_t index);

    bool verify(std::span<const uint8_t> leaf, const Hash& root_hash, const Proof& proof);

    // 内部 helper
    Hash hash_leaf(std::span<const uint8_t> data);
    Hash hash_internal(const Hash& left, const Hash& right);

} // namespace MerkleTree
} // namespace Honey::Crypto