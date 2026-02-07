#pragma once

#include "core/rbc/messages.hpp"
#include "crypto/erasure_code.hpp"
#include "crypto/merkle_tree.hpp"
#include <map>
#include <stdexec/execution.hpp>

namespace Honey::BFT::Crypto::Components {

using Byte = std::byte;
using BytesSpan = std::span<const Byte>;

struct MerkleBuildResult {
    using Hash = Honey::Crypto::MerkleTree::Hash;
    using Proof = Honey::Crypto::MerkleTree::Proof;
    using Byte = std::byte;

    Hash root;
    std::vector<std::vector<Byte>> shards; // erasure shards
    std::vector<Proof> proofs; // merkle proofs
};

template <typename Scheduler>
class MerkleMixin {
public:
    using MerkleBuildResult = Components::MerkleBuildResult;

    explicit MerkleMixin(Scheduler s)
        : scheduler_(s)
    {
    }

    static Honey::BFT::RBC::ValPayload make_val_payload(const MerkleBuildResult& tree, int node_index)
    {
        return Honey::BFT::RBC::ValPayload {
            .root_hash = tree.root,
            .proof_index = static_cast<size_t>(node_index),
            .merkle_path = tree.proofs.at(node_index).siblings,
            .stripe = tree.shards.at(node_index)
        };
    }

    auto async_build_merkle_tree(int k, int n, std::span<const std::byte> data)
    {
        return stdexec::schedule(scheduler_)
            | stdexec::then([k, n, data_vec = std::vector<Byte>(data.begin(), data.end())]() mutable -> MerkleBuildResult {
                  auto ctx = Honey::Crypto::ErasureCode::Context::create(k, n);
                  if (!ctx) {
                      throw std::system_error(ctx.error(), "Failed to create erasure context");
                  }

                  auto shards = Honey::Crypto::ErasureCode::encode(*ctx, BytesSpan(data_vec));
                  if (!shards) {
                      throw std::system_error(shards.error(), "Erasure encode failed");
                  }
                  auto tree_data = Honey::Crypto::MerkleTree::build_and_prove(*shards);

                  return MerkleBuildResult {
                      .root = tree_data.root,
                      .shards = std::move(*shards),
                      .proofs = std::move(tree_data.proofs)
                  };
              });
    }

    auto async_decode(
        int k,
        int n,
        std::span<const std::pair<int, std::vector<Byte>>> shards)
    {

        return stdexec::schedule(scheduler_)
            | stdexec::then([k, n,
                                shards_vec = std::vector<std::pair<int, std::vector<Byte>>>(shards.begin(), shards.end())]() mutable -> std::optional<std::vector<Byte>> {
                  auto ctx = Honey::Crypto::ErasureCode::Context::create(k, n);
                  if (!ctx) {
                      return std::nullopt;
                  }

                  auto r = Honey::Crypto::ErasureCode::decode(*ctx, shards_vec);
                  return r ? std::optional(*r) : std::nullopt;
              });
    }

    auto async_verify_merkle(
        BytesSpan leaf,
        size_t proof_index,
        std::span<const Honey::Crypto::MerkleTree::Hash> merkle_path,
        const Honey::Crypto::MerkleTree::Hash& root)
    {

        return stdexec::schedule(scheduler_)
            | stdexec::then([leaf_vec = std::vector<Byte>(leaf.begin(), leaf.end()),
                                proof_index,
                                path_vec = std::vector<Honey::Crypto::MerkleTree::Hash>(merkle_path.begin(), merkle_path.end()),
                                root]() mutable {
                  Honey::Crypto::MerkleTree::Proof proof {
                      .leaf_index = proof_index,
                      .siblings = std::move(path_vec)
                  };
                  return Honey::Crypto::MerkleTree::verify(BytesSpan(leaf_vec), proof, root);
              });
    }

protected:
    Scheduler scheduler_;
};

}
