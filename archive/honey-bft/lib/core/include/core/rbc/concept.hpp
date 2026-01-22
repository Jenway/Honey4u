#pragma once

#include "core/common.hpp"
#include "core/concepts.hpp"
#include "core/rbc/messages.hpp"
#include <expected>
#include <map>
#include <system_error>

namespace Honey::BFT::RBC {

using Byte = std::byte;
using BytesSpan = std::span<const Byte>;
using MutableBytesSpan = std::span<Byte>;

template <typename T>
concept Transceiver = requires(T& t, NodeId target, const RBCMessage& msg) {
    { t.unicast(target, msg) } -> Awaitable;
    { t.broadcast(msg) } -> Awaitable;
};

template <typename T>
concept CanBuildMerkleTree = requires(T& t,
    int K, int N, BytesSpan data) {
    typename T::MerkleTreeType;
    { t.async_build_merkle_tree(K, N, data) } -> AwaitableOf<typename T::MerkleTreeType>;
};

template <typename T>
concept CanExtractPayload = requires(T& t, const typename T::MerkleTreeType& tree, int node_id) {
    { t.extract_val_payload(tree, node_id) } -> std::same_as<ValPayload>;
};

template <typename T>
concept CanVerifyMerkleProof = requires(T& t,
    BytesSpan stripe, size_t proof_index, std::vector<Hash> merkle_path, const Hash& root) {
    { t.async_verify_merkle(stripe, proof_index, merkle_path, root) } -> AwaitableOf<bool>;
};

template <typename T>
concept CanDecodeShards = requires(T& t,
    const std::map<int, std::vector<Byte>>& received_shards,
    int K, int N) {
    { t.async_decode(K, N, received_shards) } -> AwaitableOf<std::expected<std::vector<Byte>, std::error_code>>;
};

template <typename T>
concept CryptoService = CanBuildMerkleTree<T> && CanVerifyMerkleProof<T> && CanDecodeShards<T> && CanExtractPayload<T>;

} // namespace Honey::BFT::RBC
