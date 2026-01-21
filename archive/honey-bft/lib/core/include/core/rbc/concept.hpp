#pragma once

#include "core/common.hpp"
#include "core/concepts.hpp"
#include "core/rbc/messages.hpp"
#include <system_error>

namespace Honey::BFT::RBC {
using Honey::Crypto::MerkleTree::Tree;

template <typename T>
concept Transceiver = requires(T& t, NodeId target, const RBCMessage& msg) {
    { t.unicast(target, msg) } -> Awaitable;
    { t.broadcast(msg) } -> Awaitable;
};

template <typename T>
concept CryptoService = requires(T& t,
    BytesSpan stripe, const Proof& proof, const Hash& root,
    const std::vector<std::vector<Byte>>& stripes,
    int K, int N, const std::map<int, std::vector<Byte>>& received_shards

) {
    { t.async_verify_merkle(stripe, proof, root) } -> AwaitableOf<bool>;
    { t.async_build_merkle_tree(K, N, BytesSpan {}) } -> AwaitableOf<Tree>;
    { t.async_decode(K, N, received_shards) } -> AwaitableOf<std::expected<std::vector<Byte>, std::error_code>>;
};
} // namespace Honey::BFT::RBC
