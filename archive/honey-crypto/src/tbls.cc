#include <algorithm>
#include <cstring>
#include <expected>
#include <iostream>
#include <random>
#include <ranges>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include "crypto/tbls.hpp"

using blst::byte;

namespace TBLS {

namespace Constants {
    constexpr std::string_view DST_SIG = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
}

[[nodiscard]]
auto dealer(int players, int k) -> std::expected<DealerResult, std::error_code>
{
    if (k < 1 || k > players)
        return std::unexpected(Error::InvalidThreshold);
    if (players < 1)
        return std::unexpected(Error::InvalidPlayerCount);

    std::vector<Fr> a;
    a.reserve(k);
    for (int i = 0; i < k; ++i)
        a.push_back(Fr::random());

    Fr secret = a[0];

    auto sk_view = std::views::iota(1, players + 1)
        | std::views::transform([&](int i) {
              return TBLSMath::polynom_eval(Fr(i), a);
          });

    std::vector<Fr> SKs = std::ranges::to<std::vector<Fr>>(sk_view);

    blst::P2 VK = blst::P2::generator();
    VK.mult(secret.val);

    auto vk_view = SKs | std::views::transform([](const Fr& sk) {
        blst::P2 v = blst::P2::generator();
        v.mult(sk.val);
        return v;
    });
    std::vector<blst::P2> VKs(vk_view.begin(), vk_view.end());

    PublicKey pk { players, k, VK, VKs };

    std::vector<PrivateKeyShare> sks;
    sks.reserve(players);
    for (int i = 0; i < players; ++i) {
        sks.push_back(PrivateKeyShare { i + 1, SKs[i], VK, VKs });
    }

    return DealerResult { std::move(pk), std::move(sks) };
}

// 签名 (Hash to G1 * SK)
blst::P1 sign_share(const PrivateKeyShare& sk_share, const std::string& msg)
{
    const std::string DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
    blst::P1 h;
    // 使用 hash_to 接口
    h.hash_to((const byte*)msg.data(), msg.size(), DST);
    // 签名 = h * sk
    h.sign_with(sk_share.sk.val);
    return h;

    // blst::P1 h;
    // // data() 返回 const char*, cast 为 const byte*
    // h.hash_to(reinterpret_cast<const byte*>(msg.data()), msg.size(),
    //     Constants::DST_SIG.data(), Constants::DST_SIG.size());
    // h.sign_with(sk_share.sk.val);
    // return h;
}

[[nodiscard]]
auto verify_share(const PublicKey& pk, int id, std::string_view msg, const blst::P1& sig)
    -> std::expected<void, std::error_code>
{
    if (id < 1 || id > pk.l) {
        return std::unexpected(Error::InvalidShareID);
    }
    const std::string DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

    // blst 需要 Affine 坐标进行 verify
    blst::P1_Affine sig_affine(sig);
    blst::P2_Affine pk_affine(pk.vks[id - 1]);

    blst::BLST_ERROR err = sig_affine.core_verify(pk_affine, true, (const byte*)msg.data(), msg.size(), DST);

    if (err != blst::BLST_SUCCESS) {
        return std::unexpected(Error::ShareVerificationFailed);
    }
    return {}; // Success
}

[[nodiscard]]
auto combine_shares(const PublicKey& pk,
    std::span<const int> ids,
    std::span<const blst::P1> sigs)
    -> std::expected<blst::P1, std::error_code>
{
    // 检查数量是否达到门限 k
    if (ids.size() != static_cast<size_t>(pk.k)) {
        return std::unexpected(Error::NotEnoughShares);
    }
    if (ids.size() != sigs.size()) {
        return std::unexpected(Error::MismatchedIdsAndSigs);
    }

    blst::P1 master_sig;

    for (const auto& [id, sig] : std::views::zip(ids, sigs)) {

        if (id < 1 || id > pk.l)
            return std::unexpected(Error::InvalidShareID);

        Fr coeff = TBLSMath::lagrange_coeff(ids, id);

        blst::P1 part = sig;
        part.mult(coeff.val);
        master_sig.add(part);
    }

    return master_sig;
}

[[nodiscard]]
auto verify_signature(const PublicKey& pk, std::string_view msg, const blst::P1& sig)
    -> std::expected<void, std::error_code>
{
    const std::string DST = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";

    blst::P1_Affine sig_affine(sig);
    blst::P2_Affine pk_affine(pk.vk);

    blst::BLST_ERROR err = sig_affine.core_verify(
        pk_affine, true, (const byte*)msg.data(), msg.size(), DST);

    if (err != blst::BLST_SUCCESS) {
        return std::unexpected(Error::SignatureVerificationFailed);
    }
    return {};
}

}
