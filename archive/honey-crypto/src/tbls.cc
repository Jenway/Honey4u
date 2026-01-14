#include "crypto/threshold/tbls.hpp"
#include "crypto/blst/P1.hpp"
#include "crypto/blst/P2.hpp"
#include "crypto/blst/Scalar.hpp"
#include "crypto/common.hpp"
#include "crypto/threshold/math.hpp"
#include <blst.h>
#include <cstring>
#include <expected>
#include <span>
#include <string>
#include <system_error>
#include <vector>

namespace Honey::Crypto::Tbls {
using Scalar = Honey::Crypto::bls::Scalar;
using P1_Affine = Honey::Crypto::bls::P1_Affine;
using P2_Affine = Honey::Crypto::bls::P2_Affine;

namespace {
    // 优化：使用 Horner's Rule (霍纳法则) 减少乘法次数
    // poly = a0 + a1*x + ... + an*x^n
    //      = a0 + x(a1 + x(a2 + ...))
    [[nodiscard]]
    inline Scalar polynom_eval(const Scalar& x, std::span<const Scalar> coeffs)
    {
        if (coeffs.empty())
            return Scalar::from_uint64(0);

        // 从高次项开始计算
        // result = coeffs[n]
        // result = result * x + coeffs[n-1]
        // ...
        Scalar res = coeffs.back();
        for (auto it = coeffs.rbegin() + 1; it != coeffs.rend(); ++it) {
            res = res * x + (*it);
        }
        return res;
    }

}

namespace Constants {
    inline const std::string DST_SIG = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
}

// 生成签名份额
[[nodiscard]]
PartialSignature sign_share(const TblsPrivateKeyShare& share, BytesSpan message)
{
    auto h = P1::from_hash(message, as_span(Constants::DST_SIG));

    h.sign_with(share.secret);

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
    int player_id )
    -> std::expected<void, std::error_code>
{
    if (player_id < 1 || player_id > params.total_players) {
        return std::unexpected(Error::InvalidShareID);
    }

    // blst 需要 Affine 坐标进行 verify
    auto sig_affine = P1_Affine::from_P1(partial_sig);
    auto pk_affine = P2_Affine::from_P2(params.verification_vector[player_id - 1]);

    BLST_ERROR err = sig_affine.core_verify(pk_affine, true, message, as_span(Constants::DST_SIG));

    if (err != BLST_SUCCESS) {
        return std::unexpected(Error::ShareVerificationFailed);
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

    auto sig_affine = P1_Affine::from_P1(signature);
    auto pk_affine = P2_Affine::from_P2(params.master_public_key);

    BLST_ERROR err = sig_affine.core_verify(
        pk_affine, true, message, as_span(Constants::DST_SIG));

    if (err != BLST_SUCCESS) {
        return std::unexpected(Error::SignatureVerificationFailed);
    }
    return {};
}

}
