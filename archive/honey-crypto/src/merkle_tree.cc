#include "crypto/merkle_tree.hpp"
#include "crypto/threshold/utils.hpp"
#include <bit>
#include <cstring>
#include <openssl/evp.h>
#include <utility>

namespace Honey::Crypto::MerkleTree {
using Crypto::impl::EvpMdCtxPtr;

namespace detail {

    constexpr Byte LEAF_PREFIX { 0x00 };
    constexpr Byte INTERNAL_PREFIX { 0x01 };

    Hash hash_leaf(BytesSpan data)
    {
        Hash h;
        unsigned int len = 0;

        EvpMdCtxPtr ctx(EVP_MD_CTX_new());
        if (!ctx) {
            return h;
        }

        // 2. 初始化为 SHA256
        if (1 != EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr)) {
            // Error
        }

        // 3. Update Prefix
        if (1 != EVP_DigestUpdate(ctx.get(), u8ptr(&LEAF_PREFIX), 1)) {
            // Error
        }

        // 4. Update Data
        if (1 != EVP_DigestUpdate(ctx.get(), u8ptr(data), data.size())) {
            // Error
        }

        // 5. Finalize
        if (1 != EVP_DigestFinal_ex(ctx.get(), u8ptr(h.data()), &len)) {
            // Error
        }

        return h;
    }

    // hash_internal 不需要改，因为它调用的是 Utils::sha256
    // 但你需要去 utils.cpp 里把 Utils::sha256 也改成 EVP 方式
    Hash hash_internal(const Hash& left, const Hash& right)
    {
        std::array<Byte, 65> buf;
        buf[0] = INTERNAL_PREFIX;
        std::memcpy(buf.data() + 1, left.data(), 32);
        std::memcpy(buf.data() + 33, right.data(), 32);

        return Utils::sha256(buf);
    }

} // namespace detail

// --- Tree 成员函数实现 ---

std::optional<Hash> Tree::root() const
{
    // 如果没有节点或只有填充的占位符（虽然 build 保证至少有 size 2 的 vector，除非空输入）
    if (nodes_.size() < 2)
        return std::nullopt;
    // 根节点始终在索引 1
    return nodes_[1];
}

std::expected<Proof, std::error_code> Tree::prove(size_t leaf_index) const
{
    if (leaf_index >= leaf_count_) {
        // 越界错误
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    // nodes_.size() 是 2*P，所以 P = size / 2
    size_t padded_leaf_count = nodes_.size() / 2;

    std::vector<Hash> siblings;
    // 预分配树高度 log2(P)
    siblings.reserve(static_cast<size_t>(std::bit_width(padded_leaf_count)));

    // 从叶子节点开始向上回溯
    // 堆式存储中，叶子节点的起始索引是 padded_leaf_count
    size_t t = leaf_index + padded_leaf_count;

    while (t > 1) {
        // t^1 是 t 的兄弟节点索引 (偶数+1, 奇数-1)
        siblings.push_back(nodes_[t ^ 1]);
        t >>= 1; // 上移一层
    }

    return Proof {
        .leaf_index = leaf_index,
        .total_leaves = leaf_count_, // 填充 Proof 中的辅助信息
        .siblings = std::move(siblings)
    };
}

// --- 非成员函数 / 友元函数实现 ---

Tree build(std::span<const std::vector<Byte>> leaves)
{
    Tree tree;

    if (leaves.empty()) {
        return tree; // 返回空树
    }

    size_t N = leaves.size();
    tree.leaf_count_ = N;

    // 计算 Padding 大小 P (最接近的 2 的幂)
    size_t P = std::bit_ceil(N);

    // 分配 2*P 大小的堆式数组
    tree.nodes_.resize(2 * P);

    // 1. 填充实际叶子 (加入前缀 hashing)
    // 堆式存储：叶子从索引 P 开始
    for (size_t i = 0; i < N; ++i) {
        tree.nodes_[P + i] = detail::hash_leaf(leaves[i]);
    }

    // 2. 填充 Padding 叶子
    // 如果 N < P，剩余部分用空数据的哈希填充
    if (N < P) {
        Hash empty_leaf_hash = detail::hash_leaf({});
        for (size_t i = N; i < P; ++i) {
            tree.nodes_[P + i] = empty_leaf_hash;
        }
    }

    // 3. 向上计算内部节点
    // 从 P-1 (最后一层内部节点的末尾) 倒推到 1 (根节点)
    for (size_t i = P - 1; i > 0; --i) {
        tree.nodes_[i] = detail::hash_internal(tree.nodes_[2 * i], tree.nodes_[2 * i + 1]);
    }

    return tree;
}

bool verify(BytesSpan leaf, const Hash& root_hash, const Proof& proof)
{
    // 1. 计算待验证数据的叶子哈希
    Hash acc = detail::hash_leaf(leaf);

    // 2. 使用 Proof 路径重构 Root
    size_t idx = proof.leaf_index;

    for (const auto& sib : proof.siblings) {
        if (idx & 1) {
            // 当前节点是右孩子 (奇数)，sib 是左孩子
            // Hash(sib || acc)
            acc = detail::hash_internal(sib, acc);
        } else {
            // 当前节点是左孩子 (偶数)，sib 是右孩子
            // Hash(acc || sib)
            acc = detail::hash_internal(acc, sib);
        }
        idx >>= 1; // 向上移动
    }

    // 3. 比较计算出的 Root 和 预期的 Root
    return acc == root_hash;
}

} // namespace Honey::Crypto::MerkleTree