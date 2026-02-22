#include "crypto/merkle/ec_code.hpp"
#include "crypto/merkle/merkle_tree.hpp"
#include "merkle/isal/merkle_hash.h"
#include <cstddef>
#include <cstring>

namespace Honey::Crypto::Merkle {

void MerkleContextDeleter::operator()(merkle_context* p) const noexcept
{
    merkle_context_free(p);
}

Context::Context(int N)
    : c_ctx(merkle_context_create(N))
{
}

Context::~Context() = default;

std::expected<MerkleResult, std::error_code>
build_and_prove(Context& ctx, const ShardBlock& shards)
{
    if (!ctx.c_ctx) {
        return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
    }

    Hash root {};
    if (merkle_build_nodes(ctx.c_ctx.get(), shards.c_block.get(),
            reinterpret_cast<unsigned char*>(root.data()))
        != 0) {
        return std::unexpected(std::make_error_code(std::errc::io_error));
    }

    const auto N = static_cast<size_t>(shards.N);
    const auto P = static_cast<size_t>(ctx.c_ctx->P);
    const unsigned char* nodes = ctx.c_ctx->nodes;

    MerkleResult result;
    result.root = root;
    result.proofs.reserve(N);

    for (size_t i = 0; i < N; ++i) {
        std::vector<Hash> siblings;
        for (size_t t = i + P; t > 1; t >>= 1U) {
            const size_t sib = t ^ 1U;
            Hash h {};
            std::memcpy(h.data(), nodes + sib * 32, 32);
            siblings.push_back(h);
        }
        result.proofs.push_back(MerkleProof { .leaf_index = static_cast<int>(i),
            .siblings = std::move(siblings) });
    }

    return result;
}

std::expected<void, std::error_code>
verify(Context& ctx, std::span<const std::byte> leaf, const MerkleProof& proof,
    const Hash& expected_root) noexcept
{
    if (!ctx.c_ctx) {
        return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
    }

    auto* md = ctx.c_ctx->md_ctx;
    const auto* leaf_ptr = reinterpret_cast<const unsigned char*>(leaf.data());

    Hash acc {};
    if (merkle_hash_leaf(md, leaf_ptr, leaf.size(),
            reinterpret_cast<unsigned char*>(acc.data()))
        != 0) {
        return std::unexpected(std::make_error_code(std::errc::io_error));
    }

    size_t idx = static_cast<size_t>(proof.leaf_index);
    for (const auto& sib : proof.siblings) {
        Hash next {};
        const auto* a = reinterpret_cast<const unsigned char*>(acc.data());
        const auto* s = reinterpret_cast<const unsigned char*>(sib.data());
        const int ret = ((idx & 1U) != 0U)
            ? merkle_hash_internal(
                  md, s, a, reinterpret_cast<unsigned char*>(next.data()))
            : merkle_hash_internal(
                  md, a, s, reinterpret_cast<unsigned char*>(next.data()));
        if (ret != 0) {
            return std::unexpected(std::make_error_code(std::errc::io_error));
        }
        acc = next;
        idx >>= 1U;
    }

    if (acc != expected_root) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    return {};
}

auto build_merkle_tree(const RsContext& rs_ctx, Context& merkle_ctx,
    std::span<const std::byte> data)
    -> std::expected<MerkleBuildResult, std::error_code>
{
    // Step 1: 创建消息缓冲区
    MessageBuffer msg;
    msg.assign(data);

    // Step 2: 纠删码编码
    auto shards_result = rs_encode(rs_ctx, msg);
    if (!shards_result) {
        return std::unexpected(shards_result.error());
    }

    // Step 3: 构建 Merkle 树
    auto tree_result = build_and_prove(merkle_ctx, *shards_result);
    if (!tree_result) {
        return std::unexpected(tree_result.error());
    }

    // Step 4: 组合结果
    return MerkleBuildResult { .root = tree_result->root,
        .shards = std::move(*shards_result),
        .proofs = std::move(tree_result->proofs) };
}

auto verify_and_decode(const RsContext& rs_ctx, Context& merkle_ctx,
    std::span<const ShardWithProof> shards_with_proofs,
    const Hash& expected_root)
    -> std::expected<MessageBuffer, std::error_code>
{
    // 首先验证所有分片的 Merkle 证明
    for (const auto& item : shards_with_proofs) {
        const auto& shard_view = item.shard;
        const auto& proof = item.proof;

        // 将分片数据转换为 span<const std::byte>
        auto shard_bytes = std::span<const std::byte> {
            reinterpret_cast<const std::byte*>(shard_view.data),
            shard_view.block_size
        };

        // 验证 Merkle 证明
        auto verify_result = verify(merkle_ctx, shard_bytes, proof, expected_root);

        if (!verify_result) {
            return std::unexpected(verify_result.error());
        }
    }

    // 所有验证通过后，提取 ShardView 进行解码
    std::vector<ShardView> shard_views;
    shard_views.reserve(shards_with_proofs.size());
    for (const auto& item : shards_with_proofs) {
        shard_views.push_back(item.shard);
    }

    // 调用 rs_decode 进行纠删码解码
    return rs_decode(rs_ctx, std::span<const ShardView> { shard_views });
}

}; // namespace Honey::Crypto::Merkle

#ifndef DOCTEST_CONFIG_DISABLE

#include "crypto/merkle/ec_code.hpp"
#include <doctest/doctest.h>
#include <string_view>
#include <vector>

namespace Honey::Crypto::Merkle {

namespace {
    std::vector<std::byte> to_bytes(std::string_view input)
    {
        std::vector<std::byte> out;
        out.reserve(input.size());
        for (unsigned char c : input) {
            out.push_back(static_cast<std::byte>(c));
        }
        return out;
    }
} // namespace

TEST_CASE(" Merkle.BuildsAndVerifiesProofs")
{
    const int K = 2;
    const int N = 4;

    auto rs_ctx_res = RsContext::create(K, N);
    REQUIRE(rs_ctx_res.has_value());

    Context ctx(N);
    MessageBuffer msg;
    msg.assign(to_bytes("merkle-test"));

    auto shards_res = rs_encode(*rs_ctx_res, msg);
    REQUIRE(shards_res.has_value());

    auto tree_res = build_and_prove(ctx, *shards_res);
    REQUIRE(tree_res.has_value());

    auto& tree = *tree_res;
    REQUIRE(tree.proofs.size() == static_cast<size_t>(N));

    for (int i = 0; i < N; ++i) {
        auto shard = shards_res->shard(i);
        auto shard_bytes = std::as_bytes(shard);
        std::vector<std::byte> leaf_bytes(shard_bytes.begin(), shard_bytes.end());
        auto verify_res = verify(ctx, leaf_bytes, tree.proofs[static_cast<size_t>(i)], tree.root);
        CHECK(verify_res.has_value());
    }
}

TEST_CASE(" Merkle.DetectsTampering")
{
    const int K = 2;
    const int N = 4;

    auto rs_ctx_res = RsContext::create(K, N);
    REQUIRE(rs_ctx_res.has_value());

    Context ctx(N);
    MessageBuffer msg;
    msg.assign(to_bytes("tamper-test"));

    auto shards_res = rs_encode(*rs_ctx_res, msg);
    REQUIRE(shards_res.has_value());

    auto tree_res = build_and_prove(ctx, *shards_res);
    REQUIRE(tree_res.has_value());

    auto& tree = *tree_res;
    auto shard = shards_res->shard(1);
    auto shard_bytes = std::as_bytes(shard);
    std::vector<std::byte> leaf_bytes(shard_bytes.begin(), shard_bytes.end());
    REQUIRE(!leaf_bytes.empty());
    leaf_bytes[0] ^= static_cast<std::byte>(0xFF);

    auto verify_res = verify(ctx, leaf_bytes, tree.proofs[1], tree.root);
    CHECK_FALSE(verify_res.has_value());
}

} // namespace Honey::Crypto::Merkle

#endif
