#pragma once

#include <exec/static_thread_pool.hpp>
#include <memory>
#include <system_error>
#include <utility>

#include "crypto/aes.hpp"
#include "crypto/merkle/merkle_tree_v2.hpp"
#include "crypto/merkle/rs_ec_code.hpp"
#include "crypto/threshold/tbls.hpp"
#include "crypto/threshold/tpke.hpp"
#include "crypto/threshold/types.hpp"

namespace Honey::Crypto {

struct CryptoContext {
    using Scheduler = exec::static_thread_pool::scheduler;

    using SystemTopology = Threshold::SystemTopology;
    using TblsParams = Tbls::TblsVerificationParameters;
    using TblsShare = Tbls::TblsPrivateKeyShare;
    using TpkeParams = Tpke::TpkeVerificationParameters;
    using TpkeShare = Tpke::TpkePrivateKeyShare;

    exec::static_thread_pool pool;

    const SystemTopology topology;
    const TblsParams tbls_params;
    const TblsShare tbls_share;
    const TpkeParams tpke_params;
    const TpkeShare tpke_share;

    Merkle::Context merkle_ctx;
    Merkle::RsContext rs_ctx;
    Aes::Context aes_ctx;

    CryptoContext(size_t n_threads, SystemTopology topo, Merkle::RsContext&& rs, Aes::Context&& ac, TblsParams tp, TblsShare ts, TpkeParams ep, TpkeShare es)
        : pool(n_threads)
        , topology(topo)
        , tbls_params(std::move(tp))
        , tbls_share(ts)
        , tpke_params(std::move(ep))
        , tpke_share(es)
        , rs_ctx(std::move(rs))
        , aes_ctx(std::move(ac))
    {
        // 在这里进行一次性校验
        // if (!tbls_share.is_valid())
        // throw std::invalid_argument("Invalid TBLS share");
        // ... 其他校验
    }

    static auto create(int K, int N, size_t threads, SystemTopology topo,
        TblsParams tbls_params, TblsShare tbls_share,
        TpkeParams tpke_params, TpkeShare tpke_share)
        -> std::expected<std::unique_ptr<CryptoContext>, std::error_code>
    {
        auto rs_res = Merkle::RsContext::create(K, N);
        if (!rs_res)
            return std::unexpected(rs_res.error());

        // Create AES context
        Aes::Context aes_ctx;

        return std::make_unique<CryptoContext>(
            threads,
            topo,
            std::move(*rs_res),
            std::move(aes_ctx),
            std::move(tbls_params),
            tbls_share,
            std::move(tpke_params),
            tpke_share);
    }
    CryptoContext(const CryptoContext&) = delete;
    auto scheduler() { return pool.get_scheduler(); }
};

namespace detail {
    template <typename Func>
    auto async_dispatch(CryptoContext& ctx, Func&& f)
    {
        return stdexec::schedule(ctx.scheduler())
            | stdexec::then(std::forward<Func>(f));
    }
}

using Merkle::Hash;
using Tbls::Signature;

static uint8_t hash_to_bit(const Signature& sig)
{
    uint8_t acc = 0;
    auto bytes = std::span(reinterpret_cast<const std::byte*>(&sig), sizeof(Signature));
    for (auto b : bytes) {
        acc ^= std::to_integer<uint8_t>(b);
    }
    return acc & 1;
}

// static Honey::BFT::RBC::ValPayload make_val_payload(const MerkleBuildResult& tree, int node_index)
// {
//     return Honey::BFT::RBC::ValPayload {
//         .root_hash = tree.root,
//         .proof_index = static_cast<size_t>(node_index),
//         .merkle_path = tree.proofs.at(node_index).siblings,
//         .stripe = tree.shards.at(node_index)
//     };
// }

/// TBLS Signing

using Tbls::PartialSignature;
using Tbls::SignatureShare;

auto async_sign_share(CryptoContext& ctx, std::vector<std::byte> msg)
{
    using Tbls::sign_share;
    return detail::async_dispatch(ctx,
        [&ctx, m = std::move(msg)]() mutable
            -> std::expected<PartialSignature, std::error_code> {
            return sign_share(ctx.tbls_share, m);
        });
}

auto async_verify_share(CryptoContext& ctx, PartialSignature signature, std::vector<std::byte> msg)
{
    using Tbls::verify_share;
    return detail::async_dispatch(ctx,
        [&ctx, signature = std::move(signature), m = std::move(msg)]() mutable
            -> std::expected<void, std::error_code> {
            return verify_share(ctx.tbls_params, signature, m);
        });
}

auto async_combine_signatures(CryptoContext& ctx, std::vector<PartialSignature> shares)
{
    using Tbls::combine_partial_signatures;
    return detail::async_dispatch(ctx,
        [&ctx, shares_vec = std::move(shares)]() mutable
            -> std::expected<Signature, std::error_code> {
            return combine_partial_signatures(ctx.tbls_params, shares_vec);
        });
}

auto async_verify_signature(CryptoContext& ctx, Signature sig, std::vector<std::byte> msg)
{
    using Tbls::verify_signature;
    return detail::async_dispatch(ctx,
        [&ctx, sig, m = std::move(msg)]() mutable
            -> std::expected<void, std::error_code> {
            return verify_signature(ctx.tbls_params, m, sig);
        });
}

/// TPKE Encryption / Decryption

auto async_encrypt(CryptoContext& ctx, std::vector<std::byte> plaintext)
{
    using Aes::encrypt;
    using Tpke::encapsulate;
    using Tpke::HybridCiphertext;

    return detail::async_dispatch(ctx,
        [&, pt = std::move(plaintext)]()
            -> std::expected<HybridCiphertext, std::error_code> {
            // Step 1: Use TPKE to encapsulate a session key
            auto [encap_key, session_key] = encapsulate(ctx.tpke_params);

            // Step 2: Use AES to encrypt the plaintext with the session key
            auto aes_result = encrypt(
                const_cast<Aes::Context&>(ctx.aes_ctx),
                std::span(session_key.data(), session_key.size()),
                std::span(reinterpret_cast<const std::byte*>(pt.data()), pt.size()));
            if (!aes_result) {
                return std::unexpected(aes_result.error());
            }

            // Step 3: Combine into HybridCiphertext
            return HybridCiphertext {
                .encapsulated_key = encap_key,
                .symmetric_ciphertext_payload = std::move(*aes_result)
            };
        });
}

auto async_decrypt_share(CryptoContext& ctx, const Tpke::EncapsulatedKey& encap_key)
{
    using Tpke::create_decryption_share;

    return detail::async_dispatch(ctx,
        [&ctx, encap_key]()
            -> std::expected<Tpke::PartialDecryptionShare, std::error_code> {
            return create_decryption_share(ctx.tpke_share, ctx.tpke_params, encap_key);
        });
}

using Tpke::HybridCiphertext;
using Tpke::PartialDecryption;

auto async_decrypt(CryptoContext& ctx, HybridCiphertext ct, std::vector<PartialDecryption> shares)
{
    using Aes::decrypt;
    using Tpke::recover_key;

    return detail::async_dispatch(ctx,
        [&ctx, ct = std::move(ct), shares_vec = std::move(shares)]()
            -> std::expected<std::vector<std::byte>, std::error_code> {
            // Step 1: Recover the session key from shares
            auto session_key_result = recover_key(
                ctx.tpke_params,
                ct.encapsulated_key,
                std::span(shares_vec.data(), shares_vec.size()));
            if (!session_key_result) {
                return std::unexpected(session_key_result.error());
            }
            auto& session_key = *session_key_result;

            // Step 2: Use AES to decrypt the ciphertext with the session key
            auto aes_result = decrypt(
                const_cast<Aes::Context&>(ctx.aes_ctx),
                std::span(session_key.data(), session_key.size()),
                std::span(ct.symmetric_ciphertext_payload.data(), ct.symmetric_ciphertext_payload.size()));

            return aes_result;
        });
}

/// Erasure Coding + Merkle Tree

auto async_build_merkle_tree(CryptoContext& ctx, std::vector<std::byte> data)
{
    using Merkle::build_and_prove;
    using Merkle::rs_encode;
    struct MerkleBuildResult {
        Merkle::Hash root;
        Merkle::ShardBlock shards;
        std::vector<Merkle::MerkleProof> proofs;
    };
    return detail::async_dispatch(ctx,

        [&ctx, d = std::move(data)]()
            -> std::expected<MerkleBuildResult, std::error_code> {
            Merkle::MessageBuffer msg;
            msg.assign(std::span<const std::byte> { d.data(), d.size() });

            auto shards = rs_encode(ctx.rs_ctx, msg);
            if (!shards) {
                return std::unexpected(shards.error());
            }

            auto tree = build_and_prove(ctx.merkle_ctx, *shards);
            if (!tree) {
                return std::unexpected(tree.error());
            }

            return MerkleBuildResult {
                .root = tree->root,
                .shards = std::move(*shards),
                .proofs = std::move(tree->proofs)
            };
        });
}

auto async_decode(CryptoContext& ctx, std::vector<std::pair<int, std::vector<std::byte>>> shards)
{
    return detail::async_dispatch(ctx,
        [&ctx, shards_vec = std::move(shards)]() mutable
            -> std::expected<std::vector<std::byte>, std::error_code> {
            std::vector<Merkle::ShardView> views;
            views.reserve(shards_vec.size());
            for (auto& item : shards_vec) {
                auto* data_ptr = reinterpret_cast<const unsigned char*>(item.second.data());
                views.push_back(Merkle::ShardView {
                    .index = item.first,
                    .data = data_ptr,
                    .block_size = item.second.size() });
            }

            Merkle::MessageBuffer out;
            auto res = Merkle::rs_decode_into(ctx.rs_ctx, std::span<const Merkle::ShardView> { views }, out);
            if (!res) {
                return std::unexpected(res.error());
            }

            auto payload = out.payload();
            return std::vector<std::byte>(payload.begin(), payload.end());
        });
}

auto async_verify_merkle(CryptoContext& ctx,
    std::vector<std::byte> leaf,
    size_t proof_index,
    std::vector<Hash> merkle_path,
    const Merkle::Hash& root)
{

    return detail::async_dispatch(ctx,
        [&ctx, leaf_vec = std::move(leaf),
            proof_index,
            path_vec = std::move(merkle_path),
            root]() mutable {
            Merkle::MerkleProof proof {
                .leaf_index = static_cast<int>(proof_index),
                .siblings = std::move(path_vec)
            };
            auto res = Merkle::verify(
                ctx.merkle_ctx,
                std::span<const std::byte> { leaf_vec.data(), leaf_vec.size() },
                proof,
                root);
            if (!res) {
                return std::unexpected(res.error());
            }
            return std::expected<bool, std::error_code> { true };
        });
}

} // namespace Honey::Crypto
