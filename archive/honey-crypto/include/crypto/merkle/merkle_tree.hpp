#pragma once
#include "crypto/merkle/isal/merkle_hash.h"
#include "crypto/types.hpp"
#include "struct.hpp"
#include <cstddef>
#include <expected>
#include <memory>
#include <span>
#include <system_error>
#include <vector>

namespace Honey::Crypto::Merkle {

using Hash = Honey::Crypto::Hash256;

struct MerkleContextDeleter {
    void operator()(merkle_context* p) const noexcept
    {
        merkle_context_free(p);
    }
};

/**
 * Merkle 哈希上下文。
 * N 须与对应 RsContext 的 N 一致，在 Context 生命周期内不变。
 */
struct Context {
    std::unique_ptr<merkle_context, MerkleContextDeleter> c_ctx;

    explicit Context(int N)
        : c_ctx(merkle_context_create(N))
    {
    }

    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    Context(Context&&) noexcept = default;
    Context& operator=(Context&&) noexcept = default;
    ~Context() = default;
};
struct MerkleProof {
    int leaf_index {};
    std::vector<Hash> siblings;
};

struct MerkleResult {
    Hash root {};
    std::vector<MerkleProof> proofs;
};

std::expected<MerkleResult, std::error_code>
build_and_prove(
    Context& ctx,
    const ShardBlock& shards);

auto verify(
    Context& ctx,
    std::span<const std::byte> leaf,
    const MerkleProof& proof,
    const Hash& expected_root) noexcept
    -> std::expected<void, std::error_code>;

} // namespace Honey::Crypto::Merkle
