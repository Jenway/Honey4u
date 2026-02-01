#pragma once

#include "core/rbc/rbc_core.hpp"
#include "crypto/erasure_code.hpp"
#include "crypto/merkle_tree.hpp"
#include "crypto/threshold/tbls.hpp"
#include "service/coin/concepts.hpp"
#include "service/rbc/concepts.hpp"
#include <exec/static_thread_pool.hpp>
#include <map>
#include <optional>
#include <stdexcept>
#include <stdexec/execution.hpp>
#include <system_error>
#include <vector>

namespace Honey::BFT::Crypto {

using Byte = std::byte;
using BytesSpan = std::span<const Byte>;

class AsyncCryptoService {
public:
    using MerkleTreeType = Honey::Crypto::MerkleTree::Tree;
    using Hash = Honey::Crypto::MerkleTree::SHA256Hash;
    using SignatureShare = Honey::Crypto::Tbls::SignatureShare;
    using Signature = Honey::Crypto::Tbls::Signature;
    using PartialSignature = Honey::Crypto::Tbls::PartialSignature;
    using ValPayload = Honey::BFT::RBC::ValPayload;

    explicit AsyncCryptoService(std::size_t num_threads = std::thread::hardware_concurrency())
        : thread_pool_(num_threads)
        , scheduler_(thread_pool_.get_scheduler())
    {
    }

    ~AsyncCryptoService()
    {
        thread_pool_.request_stop();
    }

    auto async_build_merkle_tree(int k, int n, BytesSpan data)
    {
        // 立即捕获数据副本到 Lambda 中，保证 Sender 生命周期内的内存安全
        return stdexec::schedule(scheduler_)
            | stdexec::then([k, n, data_vec = std::vector<Byte>(data.begin(), data.end())]() mutable {
                  auto ctx = Honey::Crypto::ErasureCode::Context::create(k, n);
                  if (!ctx) {
                      throw std::system_error(ctx.error(), "Failed to create erasure context");
                  }

                  auto shards = Honey::Crypto::ErasureCode::encode(*ctx, BytesSpan(data_vec));
                  if (!shards) {
                      throw std::system_error(shards.error(), "Erasure encode failed");
                  }

                  return MerkleTreeType::build(std::move(*shards));
              });
    }

    auto async_verify_merkle(
        BytesSpan leaf,
        size_t proof_index,
        std::span<const Hash> merkle_path,
        const Hash& root)
    {

        return stdexec::schedule(scheduler_)
            | stdexec::then([leaf_vec = std::vector<Byte>(leaf.begin(), leaf.end()),
                                proof_index,
                                path_vec = std::vector<Hash>(merkle_path.begin(), merkle_path.end()),
                                root]() mutable {
                  Honey::Crypto::MerkleTree::Proof proof {
                      .leaf_index = proof_index,
                      .siblings = std::move(path_vec)
                  };
                  return Honey::Crypto::MerkleTree::verify(BytesSpan(leaf_vec), proof, root);
              });
    }

    auto async_sign_share(BytesSpan message)
    {
        return stdexec::schedule(scheduler_)
            | stdexec::then([this,
                                msg_vec = std::vector<Byte>(message.begin(), message.end())]() mutable -> SignatureShare {
                  if (!private_key_share_) {
                      throw std::runtime_error("Private key share not initialized");
                  }
                  auto sig = Honey::Crypto::Tbls::sign_share(*private_key_share_, BytesSpan(msg_vec));
                  return sig.value;
              });
    }

    auto async_verify_share(
        const SignatureShare& share,
        BytesSpan message,
        int player_id)
    {

        return stdexec::schedule(scheduler_)
            | stdexec::then([this, share, player_id,
                                msg_vec = std::vector<Byte>(message.begin(), message.end())]() mutable {
                  if (!verification_params_) {
                      throw std::runtime_error("Verification parameters not initialized");
                  }
                  auto r = Honey::Crypto::Tbls::verify_share(
                      *verification_params_, share, BytesSpan(msg_vec), player_id);
                  return r.has_value();
              });
    }

    auto async_combine_signatures(std::span<const PartialSignature> shares)
    {
        return stdexec::schedule(scheduler_)
            | stdexec::then([this,
                                shares_vec = std::vector<PartialSignature>(shares.begin(), shares.end())]() mutable -> std::optional<Signature> {
                  if (!verification_params_) {
                      throw std::runtime_error("Verification parameters not initialized");
                  }
                  auto r = Honey::Crypto::Tbls::combine_partial_signatures(
                      *verification_params_, std::span(shares_vec));
                  return r ? std::optional(*r) : std::nullopt;
              });
    }

    auto async_verify_signature(const Signature& sig, BytesSpan message)
    {
        return stdexec::schedule(scheduler_)
            | stdexec::then([this, sig,
                                msg_vec = std::vector<Byte>(message.begin(), message.end())]() mutable {
                  if (!verification_params_) {
                      throw std::runtime_error("Verification parameters not initialized");
                  }
                  auto r = Honey::Crypto::Tbls::verify_signature(
                      *verification_params_, BytesSpan(msg_vec), sig);
                  return r.has_value();
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

                  std::map<int, std::vector<Byte>> shard_map;
                  for (auto& [i, d] : shards_vec) {
                      shard_map.emplace(i, std::move(d));
                  }

                  auto r = Honey::Crypto::ErasureCode::decode(*ctx, shard_map);
                  return r ? std::optional(*r) : std::nullopt;
              });
    }

    static uint8_t hash_to_bit(const Signature& sig)
    {
        uint8_t acc = 0;
        auto bytes = std::span(reinterpret_cast<const std::byte*>(&sig), sizeof(Signature));
        for (auto b : bytes) {
            acc ^= std::to_integer<uint8_t>(b);
        }
        return acc & 1;
    }

    static ValPayload extract_val_payload(const MerkleTreeType& tree, int node_index)
    {
        auto proof = tree.prove(node_index);
        if (!proof) {
            throw std::runtime_error("Failed to generate merkle proof");
        }

        std::vector<Hash> path(proof->siblings.begin(), proof->siblings.end());
        const auto& leaf = tree.leaf(node_index);

        return {
            .root_hash = tree.root(),
            .proof_index = static_cast<size_t>(node_index),
            .merkle_path = std::move(path),
            .stripe = std::vector<Byte>(leaf.begin(), leaf.end())
        };
    }

    void set_private_key_share(const Honey::Crypto::Tbls::TblsPrivateKeyShare& share)
    {
        private_key_share_ = share;
    }

    void set_verification_params(const Honey::Crypto::Tbls::TblsVerificationParameters& params)
    {
        verification_params_ = params;
    }

private:
    exec::static_thread_pool thread_pool_;
    exec::static_thread_pool::scheduler scheduler_;

    std::optional<Honey::Crypto::Tbls::TblsPrivateKeyShare> private_key_share_;
    std::optional<Honey::Crypto::Tbls::TblsVerificationParameters> verification_params_;
};

// static_assert(Honey::BFT::RBC::CryptoService<AsyncCryptoService>);

} // namespace Honey::BFT::Crypto
