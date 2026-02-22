#pragma once

#include "crypto/aes.hpp"
#include "crypto/merkle/ec_code.hpp"
#include "crypto/merkle/merkle_tree.hpp"
#include "crypto/threshold/pke.hpp"
#include "crypto/threshold/sig.hpp"
#include "crypto/threshold/types.hpp"
#include <cstring>
#include <exec/static_thread_pool.hpp>
#include <memory>
#include <system_error>
#include <utility>

namespace Honey::Crypto {

struct CryptoContext {
    using Scheduler = exec::static_thread_pool::scheduler;

    using SystemTopology = Threshold::SystemTopology;
    using SigParams = Threshold::Sig::PublicParameters;
    using SigShare = Threshold::Sig::PrivateKeyShare;
    using PkeParams = Threshold::Pke::PublicParameters;
    using PkeShare = Threshold::Pke::PrivateKeyShare;

    exec::static_thread_pool pool;

    const SystemTopology topology;
    const SigParams sig_params;
    const SigShare sig_share;
    const PkeParams pke_params;
    const PkeShare pke_share;

    Merkle::Context merkle_ctx;
    Merkle::RsContext rs_ctx;
    mutable Aes::Context aes_ctx;

    CryptoContext(size_t n_threads, SystemTopology topo, Merkle::RsContext&& rs, Aes::Context&& ac, SigParams sp, SigShare ss, PkeParams pp, PkeShare ps)
        : pool(n_threads)
        , topology(topo)
        , sig_params(std::move(sp))
        , sig_share(ss)
        , pke_params(std::move(pp))
        , pke_share(ps)
        , merkle_ctx(topo.n)
        , rs_ctx(std::move(rs))
        , aes_ctx(std::move(ac))
    {
        // 在这里进行一次性校验
        // if (!sig_share.is_valid())
        // throw std::invalid_argument("Invalid Sig share");
        // ... 其他校验
    }

    static auto create(int K, int N, size_t threads, SystemTopology topo,
        SigParams sig_params, SigShare sig_share,
        PkeParams pke_params, PkeShare pke_share)
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
            std::move(sig_params),
            sig_share,
            std::move(pke_params),
            pke_share);
    }
    CryptoContext(const CryptoContext&) = delete;
    auto scheduler() { return pool.get_scheduler(); }
};

namespace detail {
    template <typename Func>
    inline auto async_dispatch(CryptoContext& ctx, Func&& f)
    {
        return stdexec::schedule(ctx.scheduler())
            | stdexec::then(std::forward<Func>(f));
    }
}

using Merkle::Hash;
using Threshold::Sig::Signature;

/// Threshold Signing

using Threshold::Sig::PartialSignature;
using Threshold::Sig::SignatureShare;

inline auto async_sign_share(CryptoContext& ctx, std::vector<std::byte> msg)
{
    using Threshold::Sig::sign;
    return detail::async_dispatch(ctx,
        [&ctx, m = std::move(msg)]() mutable
            -> PartialSignature {
            return sign(ctx.sig_share, m);
        });
}

inline auto async_verify_share(CryptoContext& ctx, PartialSignature signature, std::vector<std::byte> msg)
{
    using Threshold::Sig::verify_share;
    return detail::async_dispatch(ctx,
        [&ctx, signature = signature, m = std::move(msg)]() mutable
            -> std::expected<void, std::error_code> {
            return verify_share(ctx.sig_params, signature, m);
        });
}

inline auto async_validate_signatures(CryptoContext& ctx, std::vector<PartialSignature> shares, std::vector<std::byte> msg)
{
    using Threshold::Sig::validate;
    return detail::async_dispatch(ctx,
        [&ctx, shares_vec = std::move(shares), m = std::move(msg)]() mutable
            -> std::expected<void, std::error_code> {
            return validate(ctx.sig_params, m, shares_vec);
        });
}

/// Threshold PKE Encryption / Decryption

struct HybridCiphertext {
    Threshold::Pke::Ciphertext tpke_ciphertext;
    std::vector<std::byte> symmetric_ciphertext;
};

inline auto async_encrypt(CryptoContext& ctx, std::vector<std::byte> plaintext)
{
    using Aes::encrypt;
    using Threshold::Pke::PlainText;
    using Threshold::Pke::seal;

    return detail::async_dispatch(ctx,
        [&, pt = std::move(plaintext)]()
            -> std::expected<HybridCiphertext, std::error_code> {
            // Step 1: Generate random session key (32 bytes)
            PlainText session_key;
            // TODO: Fill with random bytes
            std::memset(session_key.data(), 0, session_key.size());

            // Step 2: Use TPKE to seal the session key
            auto tpke_ct = seal(ctx.pke_params.master_public_key, session_key);

            // Step 3: Use AES to encrypt the plaintext with the session key
            Aes::AesKey aes_key;
            std::memcpy(aes_key.data(), session_key.data(), session_key.size());
            auto aes_result = encrypt(
                ctx.aes_ctx,
                aes_key,
                std::span(pt.data(), pt.size()));
            if (!aes_result) {
                return std::unexpected(aes_result.error());
            }

            // Step 4: Combine into HybridCiphertext
            return HybridCiphertext {
                .tpke_ciphertext = tpke_ct,
                .symmetric_ciphertext = std::move(*aes_result)
            };
        });
}

inline auto async_decrypt_share(CryptoContext& ctx, const Threshold::Pke::Ciphertext& ciphertext)
{
    using Threshold::Pke::partial_open;

    return detail::async_dispatch(ctx,
        [&ctx, ciphertext]()
            -> std::expected<Threshold::Pke::PartialDecryptionShare, std::error_code> {
            return partial_open(ctx.pke_share, ciphertext);
        });
}

using Threshold::Pke::PartialDecryptionShare;

inline auto async_decrypt(CryptoContext& ctx, HybridCiphertext ct, std::vector<PartialDecryptionShare> shares)
{
    using Aes::decrypt;
    using Threshold::Pke::open;

    return detail::async_dispatch(ctx,
        [&ctx, ct = std::move(ct), shares_vec = std::move(shares)]()
            -> std::expected<std::vector<std::byte>, std::error_code> {
            // Step 1: Recover the session key from shares
            auto session_key_result = open(
                ctx.pke_params,
                ct.tpke_ciphertext,
                std::span(shares_vec.data(), shares_vec.size()));
            if (!session_key_result) {
                return std::unexpected(session_key_result.error());
            }
            auto& session_key = *session_key_result;

            // Step 2: Use AES to decrypt the ciphertext with the session key
            Aes::AesKey aes_key;
            std::memcpy(aes_key.data(), session_key.data(), session_key.size());
            auto aes_result = decrypt(
                ctx.aes_ctx,
                aes_key,
                std::span(ct.symmetric_ciphertext.data(), ct.symmetric_ciphertext.size()));

            return aes_result;
        });
}

/// Erasure Coding + Merkle Tree

inline auto async_build_merkle_tree(CryptoContext& ctx, std::vector<std::byte> data)
{
    using Merkle::build_merkle_tree;
    using Merkle::MerkleBuildResult;

    return detail::async_dispatch(ctx,
        [&ctx, d = std::move(data)]()
            -> std::expected<MerkleBuildResult, std::error_code> {
            return build_merkle_tree(
                ctx.rs_ctx,
                ctx.merkle_ctx,
                std::span<const std::byte> { d.data(), d.size() });
        });
}

inline auto async_decode(CryptoContext& ctx, std::vector<std::pair<int, std::vector<std::byte>>> shards)
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

            auto msg_res = Merkle::rs_decode(ctx.rs_ctx, std::span<const Merkle::ShardView> { views });
            if (!msg_res) {
                return std::unexpected(msg_res.error());
            }

            auto payload = msg_res->payload();
            return std::vector<std::byte>(payload.begin(), payload.end());
        });
}

inline auto async_verify_merkle(CryptoContext& ctx,
    std::vector<std::byte> leaf,
    size_t proof_index,
    std::vector<Hash> merkle_path,
    const Merkle::Hash& root)
{

    return detail::async_dispatch(ctx,
        [&ctx, leaf_vec = std::move(leaf),
            proof_index,
            path_vec = std::move(merkle_path),
            root]() mutable -> std::expected<void, std::error_code> {
            Merkle::MerkleProof proof {
                .leaf_index = static_cast<int>(proof_index),
                .siblings = std::move(path_vec)
            };
            return Merkle::verify(
                ctx.merkle_ctx,
                std::span<const std::byte> { leaf_vec.data(), leaf_vec.size() },
                proof,
                root);
        });
}

} // namespace Honey::Crypto
