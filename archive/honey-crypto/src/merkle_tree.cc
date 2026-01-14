#include "crypto/merkle_tree.hpp"
#include <algorithm> // std::copy
#include <bit> // C++20 std::bit_ceil
#include <openssl/sha.h> // 直接调用 OpenSSL 以获得最高性能
#include <stdexcept>
namespace Honey::Crypto {
namespace MerkleTree {

    constexpr uint8_t LEAF_PREFIX = 0x00;
    constexpr uint8_t INTERNAL_PREFIX = 0x01;

    inline Hash sha256_raw(const uint8_t* data, size_t len)
    {
        Hash h;
        SHA256(data, len, h.data());
        return h;
    }

    Hash hash_leaf(std::span<const uint8_t> data)
    {
        // 构造 buffer: [0x00, data...]
        // 这里为了避免 vector 分配，可以使用 OpenSSL 的 Init/Update/Final 接口
        // 或者如果 data 不大，拷贝一次也行。为了通用性使用 Update 模式。
        Hash h;
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, &LEAF_PREFIX, 1); // 写入前缀
        SHA256_Update(&ctx, data.data(), data.size());
        SHA256_Final(h.data(), &ctx);
        return h;
    }

    Hash hash_internal(const Hash& left, const Hash& right)
    {
        // 构造 buffer: [0x01, left, right]
        // 总长度固定 1 + 32 + 32 = 65 字节，完全可以在栈上分配
        uint8_t buf[65];
        buf[0] = INTERNAL_PREFIX;
        std::copy(left.begin(), left.end(), buf + 1);
        std::copy(right.begin(), right.end(), buf + 33);

        return sha256_raw(buf, 65);
    }

    Tree build(std::span<const std::vector<uint8_t>> leaves)
    {
        if (leaves.empty())
            return { 0, 0, {} };

        size_t N = leaves.size();
        // C++20 std::bit_ceil: 如果 N=5 返回 8，如果 N=8 返回 8
        size_t P = std::bit_ceil(N);

        // 一次性分配内存，Hash 是 array，所以这是单纯的一大块连续内存
        std::vector<Hash> nodes(2 * P);

        // 填充叶子 (加入前缀 hashing)
        for (size_t i = 0; i < N; ++i) {
            nodes[P + i] = hash_leaf(leaves[i]);
        }

        // Padding: 这里的语义是对“空字节数组”进行 leaf hash
        // 或者是用全零 Hash？通常 Merkle Tree 补全用的是空值的 Hash。
        Hash empty_leaf_hash = hash_leaf({});
        for (size_t i = N; i < P; ++i) {
            nodes[P + i] = empty_leaf_hash;
        }

        // 向上构建 (加入前缀 hashing)
        for (size_t i = P - 1; i > 0; --i) {
            nodes[i] = hash_internal(nodes[2 * i], nodes[2 * i + 1]);
        }

        return { N, P, std::move(nodes) };
    }

    std::optional<Hash> root(const Tree& tree)
    {
        if (tree.nodes.size() < 2)
            return std::nullopt;
        return tree.nodes[1];
    }

    Proof prove(const Tree& tree, size_t index)
    {
        if (index >= tree.leaf_count)
            throw std::out_of_range("Merkle proof index out of range");

        std::vector<Hash> siblings;
        // 预分配 log2(P) 大小，避免 push_back 扩容
        siblings.reserve(std::bit_width(tree.padded_leaf_count));

        size_t t = index + tree.padded_leaf_count;

        while (t > 1) {
            siblings.push_back(tree.nodes[t ^ 1]);
            t >>= 1;
        }

        return { index, std::move(siblings) };
    }

    bool verify(
        std::span<const uint8_t> leaf,
        const Hash& root_hash,
        const Proof& proof)
    {
        Hash acc = hash_leaf(leaf);
        size_t idx = proof.index;

        for (const auto& sib : proof.siblings) {
            if (idx & 1)
                acc = hash_internal(sib, acc); // sib is left
            else
                acc = hash_internal(acc, sib); // acc is left
            idx >>= 1;
        }

        return acc == root_hash;
    }

} // namespace MerkleTree
} // namespace Honey::Crypto