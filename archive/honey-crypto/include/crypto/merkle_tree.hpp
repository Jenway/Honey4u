#pragma once

#include <array>
#include <cstddef>
#include <expected>
#include <optional>
#include <span>
#include <system_error>
#include <vector>

#include "crypto/common.hpp"

namespace Honey::Crypto::MerkleTree {

// 明确 Hash 大小
using Hash = std::array<Byte, 32>;

struct Proof {
    size_t leaf_index; // 验证时需要知道是第几个叶子
    size_t total_leaves; // (可选) 验证时有时需要总数来检查边界
    std::vector<Hash> siblings; // 默克尔路径
};

class Tree {
public:
    Tree() = default;

    [[nodiscard]] std::optional<Hash> root() const;

    // 生成证明
    [[nodiscard]] std::expected<Proof, std::error_code> prove(size_t leaf_index) const;

    // 获取底层存储（如果用于调试或序列化）
    [[nodiscard]] const std::vector<Hash>& nodes() const { return nodes_; }
    [[nodiscard]] size_t leaf_count() const { return leaf_count_; }

private:
    friend Tree build(std::span<const std::vector<Byte>> leaves);

    size_t leaf_count_ = 0;
    // 对应 Python 中的 2 * bottomrow，依然是 array-based tree
    std::vector<Hash> nodes_;
};

// 构建函数
// 注意：这里参数如果不打算改模板，建议加上 const
[[nodiscard]]
Tree build(std::span<const std::vector<Byte>> leaves);

// 验证函数
// 不需要传入 Tree 对象，只需要 Root Hash
// leaf: 待验证的原始数据
[[nodiscard]]
bool verify(BytesSpan leaf, const Hash& root_hash, const Proof& proof);

// --- 内部 Helper (通常放入 detail 命名空间或私有) ---
namespace detail {
    // 实现域分离: Hash(0x00 || data)
    Hash hash_leaf(BytesSpan data);

    // 实现域分离: Hash(0x01 || left || right)
    Hash hash_internal(const Hash& left, const Hash& right);
}

} // namespace Honey::Crypto::MerkleTree