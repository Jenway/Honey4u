#include "crypto/merkle_tree.hpp"
#include "impl_utils.hpp"
#include <bit>
#include <cstring>
#include <expected>
#include <openssl/evp.h>

namespace Honey::Crypto::MerkleTree {

// using namespace Honey::Crypto::impl;

namespace {
    constexpr Byte LEAF_PREFIX { 0x00 };
    constexpr Byte INTERNAL_PREFIX { 0x01 };

    std::expected<Hash, std::error_code> hash_leaf(EVP_MD_CTX* ctx, BytesSpan data)
    {
        Hash h;
        unsigned int len = 0;
        if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) || 1 != EVP_DigestUpdate(ctx, u8ptr(&LEAF_PREFIX), 1) || 1 != EVP_DigestUpdate(ctx, u8ptr(data), data.size()) || 1 != EVP_DigestFinal_ex(ctx, u8ptr(h.data()), &len)) {
            return std::unexpected(std::make_error_code(std::errc::io_error));
        }
        return h;
    }

    std::expected<Hash, std::error_code> hash_internal(EVP_MD_CTX* ctx, const Hash& left, const Hash& right)
    {
        Hash h;
        unsigned int len;
        if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) || 1 != EVP_DigestUpdate(ctx, u8ptr(&INTERNAL_PREFIX), 1) || 1 != EVP_DigestUpdate(ctx, left.data(), left.size()) || 1 != EVP_DigestUpdate(ctx, right.data(), right.size()) || 1 != EVP_DigestFinal_ex(ctx, u8ptr(h.data()), &len)) {
            return std::unexpected(std::make_error_code(std::errc::io_error));
        }
        return h;
    }

} // namespace

TreeData build_and_prove(std::span<const std::vector<Byte>> leaves)
{
    if (leaves.empty()) {
        return TreeData {};
    }

    impl::EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx)
        return {};

    const size_t N = leaves.size();
    const size_t P = std::bit_ceil(N);

    std::vector<Hash> nodes(2 * P);

    // 1. Hash actual leaves
    for (size_t i = 0; i < N; ++i) {
        if (auto res = hash_leaf(ctx.get(), leaves[i]); res)
            nodes[P + i] = *res;
        else
            return {};
    }

    // 2. Hash padding leaves
    if (N < P) {
        auto res = hash_leaf(ctx.get(), {});
        if (!res)
            return {};
        for (size_t i = N; i < P; ++i) {
            nodes[P + i] = *res;
        }
    }

    // 3. Hash internal nodes
    for (size_t i = P - 1; i > 0; --i) {
        auto res = hash_internal(ctx.get(), nodes[2 * i], nodes[(2 * i) + 1]);
        if (!res)
            return {};
        nodes[i] = *res;
    }

    TreeData result;
    result.root = nodes[1];
    result.proofs.reserve(N);

    const size_t padded_leaf_count = P;
    for (size_t i = 0; i < N; ++i) {
        std::vector<Hash> siblings;
        siblings.reserve(std::bit_width(padded_leaf_count));

        for (size_t t = i + padded_leaf_count; t > 1; t >>= 1U) {
            siblings.push_back(nodes[t ^ 1U]);
        }

        result.proofs.push_back(Proof {
            .leaf_index = i,
            .siblings = std::move(siblings) });
    }

    return result;
}

bool verify(BytesSpan leaf, const Proof& proof, const Hash& root) noexcept
{
    impl::EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx)
        return false;

    auto acc_res = hash_leaf(ctx.get(), leaf);
    if (!acc_res)
        return false;

    Hash acc = *acc_res;
    size_t idx = proof.leaf_index;

    for (const auto& sib : proof.siblings) {
        std::expected<Hash, std::error_code> next_acc_res;
        if ((idx & 1) != 0U) { // Current node is a right child
            next_acc_res = hash_internal(ctx.get(), sib, acc);
        } else { // Current node is a left child
            next_acc_res = hash_internal(ctx.get(), acc, sib);
        }
        if (!next_acc_res)
            return false;
        acc = *next_acc_res;
        idx >>= 1U;
    }
    return acc == root;
}

} // namespace Honey::Crypto::MerkleTree
