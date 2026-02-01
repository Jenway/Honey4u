#pragma once

#include "core/common.hpp"
#include "core/rbc/rbc_core.hpp"
#include "service/concepts.hpp"
#include <optional>
#include <span>
#include <vector>

namespace Honey::BFT::RBC {

using Byte = std::byte;
using BytesSpan = std::span<const Byte>;

template <typename T>
concept Transceiver = requires(T& t, NodeId target, const RBCMessage& msg) {
    { t.unicast(target, msg) } -> Sender;
    { t.broadcast(msg) } -> Sender;
};

template <typename T>
concept CanBuildMerkleTree = requires(T& t, int K, int N, BytesSpan data) {
    typename T::MerkleTreeType;
    { t.async_build_merkle_tree(K, N, data) } -> SenderOf<typename T::MerkleTreeType>;
};

template <typename T>
concept CanExtractPayload = requires(T& t, const typename T::MerkleTreeType& tree, int node_id) {
    { t.extract_val_payload(tree, node_id) } -> std::same_as<ValPayload>;
};

template <typename T>
concept CanVerifyMerkleProof = requires(T& t,
    BytesSpan stripe, size_t proof_index, std::span<const Hash> merkle_path, const Hash& root) {
    { t.async_verify_merkle(stripe, proof_index, merkle_path, root) } -> SenderOf<bool>;
};

template <typename T>
concept CanDecodeShards = requires(T& t,
    int K, int N,
    std::span<const std::pair<int, std::vector<Byte>>> shards) {
    { t.async_decode(K, N, shards) } -> SenderOf<std::optional<std::vector<Byte>>>;
};

template <typename T>
concept CryptoService = CanBuildMerkleTree<T> && CanVerifyMerkleProof<T> && CanDecodeShards<T> && CanExtractPayload<T>;

} // namespace Honey::BFT::RBC
