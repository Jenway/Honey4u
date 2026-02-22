#pragma once
#include "crypto/types.hpp"
#include "isal_fwd.hpp"
#include "struct.hpp"
#include <cstddef>
#include <expected>
#include <memory>
#include <span>
#include <system_error>
#include <vector>


namespace Honey::Crypto::Merkle {

using Hash = Honey::Crypto::Hash256;

// Forward declaration
struct RsContext;

struct MerkleContextDeleter {
    void operator()(merkle_context* p) const noexcept;
};

/**
 * Merkle 哈希上下文。
 * N 须与对应 RsContext 的 N 一致，在 Context 生命周期内不变。
 */
struct Context {
    std::unique_ptr<merkle_context, MerkleContextDeleter> c_ctx;

    explicit Context(int N);
    ~Context();
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    Context(Context&&) noexcept = default;
    Context& operator=(Context&&) noexcept = default;
};
struct MerkleProof {
    int leaf_index {};
    std::vector<Hash> siblings;
};

struct MerkleResult {
    Hash root {};
    std::vector<MerkleProof> proofs;
};

struct MerkleBuildResult {
    Hash root;
    ShardBlock shards;
    std::vector<MerkleProof> proofs;
};

std::expected<MerkleResult, std::error_code>
build_and_prove(
    Context& ctx,
    const ShardBlock& shards);

/**
 * @brief 组合函数：对数据进行纠删码编码并构建 Merkle 树
 *
 * 这个函数组合了 rs_encode 和 build_and_prove 的功能，
 * 减少了 C/C++ wrapper 的转换开销。
 *
 * @param rs_ctx 纠删码上下文
 * @param merkle_ctx Merkle 树上下文
 * @param data 原始数据
 * @return 编码后的分片、Merkle 根哈希和证明
 */
auto build_merkle_tree(
    const RsContext& rs_ctx,
    Context& merkle_ctx,
    std::span<const std::byte> data)
    -> std::expected<MerkleBuildResult, std::error_code>;

auto verify(
    Context& ctx,
    std::span<const std::byte> leaf,
    const MerkleProof& proof,
    const Hash& expected_root) noexcept
    -> std::expected<void, std::error_code>;

struct ShardWithProof {
    ShardView shard {};
    MerkleProof proof {};
};

/**
 * @brief 组合函数：验证分片的 Merkle 证明并进行纠删码解码
 *
 * 这个函数组合了批量 verify 和 rs_decode 的功能，
 * 减少了 C/C++ wrapper 的转换开销，并确保只解码通过验证的分片。
 *
 * @param rs_ctx 纠删码上下文
 * @param merkle_ctx Merkle 树上下文
 * @param shards_with_proofs 分片及其证明
 * @param expected_root 期望的 Merkle 根哈希
 * @return 解码后的原始数据
 */
auto verify_and_decode(
    const RsContext& rs_ctx,
    Context& merkle_ctx,
    std::span<const ShardWithProof> shards_with_proofs,
    const Hash& expected_root)
    -> std::expected<MessageBuffer, std::error_code>;

} // namespace Honey::Crypto::Merkle
