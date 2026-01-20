#pragma once

#include "crypto/common.hpp"
#include <array>
#include <cstddef>
#include <expected>
#include <ranges>
#include <system_error>
#include <vector>

namespace Honey::Crypto::MerkleTree {

using Hash = std::array<Byte, 32>;

struct Proof {
    size_t leaf_index;
    std::vector<Hash> siblings;
};

class Tree {
public:
    using value_type = std::vector<Byte>;
    using reference = const std::vector<Byte>&;
    using const_reference = const std::vector<Byte>&;
    using iterator = std::vector<std::vector<Byte>>::const_iterator;
    using const_iterator = std::vector<std::vector<Byte>>::const_iterator;
    using size_type = std::vector<std::vector<Byte>>::size_type;

    Tree() = default;

    [[nodiscard]]
    static Tree build(std::vector<std::vector<Byte>>&& leaves);

    [[nodiscard]] const Hash& root() const noexcept { return root_hash_; }
    [[nodiscard]] std::expected<Proof, std::error_code> prove(size_type leaf_index) const;
    [[nodiscard]] const_reference leaf(size_type leaf_index) const;

    [[nodiscard]] const_iterator begin() const noexcept { return leaves_.begin(); }
    [[nodiscard]] const_iterator cbegin() const noexcept { return leaves_.cbegin(); }
    [[nodiscard]] const_iterator end() const noexcept { return leaves_.end(); }
    [[nodiscard]] const_iterator cend() const noexcept { return leaves_.end(); }

    [[nodiscard]] size_type size() const noexcept { return leaves_.size(); }
    [[nodiscard]] bool empty() const noexcept { return leaves_.empty(); }

private:
    Hash root_hash_ {};
    std::vector<Hash> nodes_;
    std::vector<std::vector<Byte>> leaves_;
};

[[nodiscard]]
bool verify(BytesSpan leaf, const Proof& proof, const Hash& root) noexcept;

static_assert(std::ranges::random_access_range<Tree>);
static_assert(std::ranges::sized_range<Tree>);

} // namespace Honey::Crypto::MerkleTree
