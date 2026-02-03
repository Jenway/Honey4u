#include "crypto/threshold/tbls.hpp"
#include "blst/ops.hpp"
#include "crypto/blst/P1.hpp"
#include "crypto/blst/P2.hpp"
#include "crypto/blst/Scalar.hpp"
#include "threshold/interpolate.hpp"
#include "threshold/key_gen.hpp"
#include <cstring>
#include <expected>
#include <span>
#include <string_view>
#include <system_error>
#include <vector>

namespace Honey::Crypto::Tbls {
using Scalar = Honey::Crypto::bls::Scalar;
using P1_Affine = Honey::Crypto::bls::P1_Affine;
using P2_Affine = Honey::Crypto::bls::P2_Affine;

namespace Constants {
    inline constexpr std::string_view DST_SIG = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
} // namespace Constants

auto generate_keys(int players, int k) -> std::expected<TblsKeySet, std::error_code>
{
    return Threshold::generate_keys<MasterPublicKey, VerificationKey>(players, k);
}

// 生成签名份额
[[nodiscard]]
PartialSignature sign_share(const TblsPrivateKeyShare& share, BytesSpan message)
{
    auto h = P1::from_hash(message, as_span(Constants::DST_SIG));

    bls::ops::sign_with(h, share.secret);

    return PartialSignature {
        .player_id = share.player_id,
        .value = h,
    };
}

// 验证单个签名份额
[[nodiscard]] auto verify_share(
    const TblsVerificationParameters& params,
    const SignatureShare& partial_sig,
    BytesSpan message,
    int player_id)
    -> std::expected<void, std::error_code>
{
    if (player_id < 1 || player_id > params.total_players) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    // auto sig_affine = P1_Affine::from_P1(partial_sig);
    // auto pk_affine = P2_Affine::from_P2(params.verification_vector[player_id - 1]);
    // auto err = sig_affine.core_verify(pk_affine, true, message, as_span(Constants::DST_SIG));
    auto err = bls::ops::core_verify_pk_in_g2(
        partial_sig,
        params.verification_vector[player_id - 1],
        true,
        message,
        as_span(Constants::DST_SIG),
        {});
    if (err) {
        return std::unexpected(err);
    }
    return {}; // Success
}

[[nodiscard]]
auto combine_partial_signatures(
    const TblsVerificationParameters& public_params,
    std::span<const PartialSignature> partial_signatures)
    -> std::expected<Signature, std::error_code>
{
    if (partial_signatures.size() != static_cast<size_t>(public_params.threshold)) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    return Crypto::Math::interpolate_at_zero(partial_signatures);
}

[[nodiscard]]
auto verify_signature(const TblsVerificationParameters& params,
    BytesSpan message,
    const Signature& signature)
    -> std::expected<void, std::error_code>
{

    // auto sig_affine = P1_Affine::from_P1(signature);
    // auto pk_affine = P2_Affine::from_P2(params.master_public_key);

    // auto err = sig_affine.core_verify(pk_affine, true, message, as_span(Constants::DST_SIG));

    auto err = bls::ops::core_verify_pk_in_g2(
        signature,
        params.master_public_key,
        true,
        message,
        as_span(Constants::DST_SIG),
        {});

    if (err) {
        return std::unexpected(err);
    }
    return {};
}

} // namespace Honey::Crypto::Tbls
