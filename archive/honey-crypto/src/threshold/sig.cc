#include "crypto/threshold/sig.hpp"
#include "blst/ops.hpp"
#include "threshold/interpolate.hpp"
#include "threshold/key_gen.hpp"
#include <cstdint>
#include <cstring>
#include <expected>
#include <span>
#include <string_view>
#include <system_error>
#include <vector>

namespace Honey::Crypto::Threshold::Sig {

namespace Constants {
    inline constexpr std::string_view DST_SIG = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_";
} // namespace Constants

namespace {

    [[nodiscard]]
    auto combine_partial_signatures(
        const PublicParameters& public_params,
        std::span<const PartialSignature> partial_signatures)
        -> std::expected<Signature, std::error_code>
    {
        if (partial_signatures.size() != static_cast<size_t>(public_params.threshold)) {
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        }

        return Crypto::Math::interpolate_at_zero(partial_signatures);
    }

    [[nodiscard]]
    auto verify_signature(const PublicParameters& params, BytesSpan message,
        const Signature& signature)
        -> std::expected<void, std::error_code>
    {

        auto err = bls::ops::core_verify_pk_in_g2(signature, params.master_public_key, true,
            message, as_span(Constants::DST_SIG), {});

        if (err) {
            return std::unexpected(err);
        }
        return {};
    }
}; // namespace
auto generate_keys(uint32_t players, uint32_t k)
    -> std::expected<KeySet, std::error_code>
{
    return Threshold::generate_keys<MasterPublicKey, VerificationKey>(players, k);
}

// 生成签名份额
[[nodiscard]]
PartialSignature sign(const PrivateKeyShare& share, BytesSpan message)
{
    auto h = bls::P1::from_hash(message, as_span(Constants::DST_SIG));

    bls::ops::sign_with(h, share.secret);

    return PartialSignature {
        .player_id = share.player_id,
        .value = h,
    };
}

// 验证单个签名份额
[[nodiscard]] auto verify_share(const PublicParameters& params,
    const PartialSignature& partial_signature,
    BytesSpan message)
    -> std::expected<void, std::error_code>
{
    const auto& partial_sig = partial_signature.value;
    int player_id = partial_signature.player_id;

    if (player_id < 1 || player_id > params.total_players) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    auto err = bls::ops::core_verify_pk_in_g2(
        partial_sig, params.verification_vector[player_id - 1], true, message,
        as_span(Constants::DST_SIG), {});
    if (err) {
        return std::unexpected(err);
    }
    return {}; // Success
}

[[nodiscard]]
auto validate(const PublicParameters& public_params, BytesSpan message,
    std::span<const PartialSignature> partial_signatures)
    -> std::expected<void, std::error_code>
{
    for (const auto& partial_sig : partial_signatures) {
        auto verify_result = verify_share(public_params, partial_sig, message);
        if (!verify_result) {
            return std::unexpected(verify_result.error());
        }
    }
    auto combined_sig_result = combine_partial_signatures(public_params, partial_signatures);
    if (!combined_sig_result) {
        return std::unexpected(combined_sig_result.error());
    }
    return verify_signature(public_params, message, *combined_sig_result);
}

} // namespace Honey::Crypto::Threshold::Sig

// ====================================================
// ==================== Unit Tests ====================
// ====================================================

#ifndef DOCTEST_CONFIG_DISABLE
#include <doctest/doctest.h>
#include <string>
#include <vector>

namespace Honey::Crypto::Threshold::Sig {

struct SigFixture {
    static constexpr int N = 10;
    static constexpr int K = 5;

    KeySet ks;

    SigFixture()
        : ks(*generate_keys(N, K))
    {
    }

    PublicParameters& params() { return ks.public_params; }
    std::vector<PrivateKeyShare>& shares() { return ks.private_shares; }
};

TEST_CASE("ThresholdSig.EndToEndFlow")
{
    constexpr int N = 10;
    constexpr int K = 5;

    auto result = generate_keys(N, K);
    REQUIRE(result.has_value());

    const auto& ks = *result;
    const auto& params = ks.public_params;
    const auto& shares = ks.private_shares;

    CHECK_EQ(params.total_players, N);
    CHECK_EQ(params.threshold, K);

    std::string msg = "HoneyBadger-GTest";

    std::vector<PartialSignature> partials;
    for (int id = 1; id <= K; ++id) {
        auto ps = sign(shares[id - 1], as_span(msg));

        auto vr = verify_share(params, ps, as_span(msg));
        CHECK(vr.has_value());

        partials.push_back(ps);
    }

    REQUIRE_EQ(partials.size(), K);

    auto final_verify = validate(params, as_span(msg), partials);
    CHECK(final_verify.has_value());
}

TEST_CASE("ThresholdSig.NotEnoughShares")
{
    constexpr int N = 10;
    constexpr int K = 5;

    auto result = generate_keys(N, K);
    REQUIRE(result.has_value());

    const auto& params = result->public_params;
    const auto& shares = result->private_shares;

    std::string msg = "FailTest";

    std::vector<PartialSignature> partials;
    for (int id = 1; id <= 2; ++id) {
        partials.push_back(sign(shares[id - 1], as_span(msg)));
    }

    auto res = validate(params, as_span(msg), partials);
    CHECK_FALSE(res.has_value());
}

TEST_CASE("ThresholdSig.InvalidShareVerification")
{
    constexpr int N = 10;
    constexpr int K = 5;

    auto result = generate_keys(N, K);
    REQUIRE(result.has_value());

    const auto& params = result->public_params;
    const auto& shares = result->private_shares;

    std::string msg = "CorrectMessage";
    std::string wrong = "WrongMessage";

    auto ps = sign(shares[0], as_span(msg));

    auto vr = verify_share(params, ps, as_span(wrong));
    CHECK_FALSE(vr.has_value());
}

TEST_CASE("ThresholdSig.DuplicatePlayerIds")
{
    constexpr int N = 5;
    constexpr int K = 3;

    auto result = generate_keys(N, K);
    REQUIRE(result.has_value());

    const auto& params = result->public_params;
    const auto& shares = result->private_shares;

    std::string msg = "DupTest";

    auto p1 = sign(shares[0], as_span(msg));
    auto p2 = sign(shares[0], as_span(msg)); // same player id
    auto p3 = sign(shares[1], as_span(msg));

    std::vector<PartialSignature> partials { p1, p2, p3 };

    auto res = validate(params, as_span(msg), partials);
    CHECK_FALSE(res.has_value());
}

TEST_CASE("ThresholdSig.InvalidPlayerId")
{
    constexpr int N = 5;
    constexpr int K = 3;

    auto result = generate_keys(N, K);
    REQUIRE(result.has_value());

    auto params = result->public_params;
    auto shares = result->private_shares;

    std::string msg = "BadId";

    auto ps = sign(shares[0], as_span(msg));
    ps.player_id = N + 1; // 非法 ID

    std::vector<PartialSignature> partials { ps };

    auto res = validate(params, as_span(msg), partials);
    CHECK_FALSE(res.has_value());
}

TEST_CASE_FIXTURE(SigFixture, "validate")
{
    const auto& params = SigFixture::params();
    auto& shares = SigFixture::shares();
    std::string msg = "HoneyBadger-GTest";

    SUBCASE("valid K shares")
    {
        std::vector<PartialSignature> partials;
        for (int id = 1; id <= K; ++id) {
            auto ps = sign(shares[id - 1], as_span(msg));
            CHECK(verify_share(params, ps, as_span(msg)));
            partials.push_back(ps);
        }

        CHECK(validate(params, as_span(msg), partials));
    }

    SUBCASE("not enough shares")
    {
        std::vector<PartialSignature> partials;
        for (int id = 1; id <= 2; ++id)
            partials.push_back(sign(shares[id - 1], as_span(msg)));

        CHECK_FALSE(validate(params, as_span(msg), partials));
    }

    SUBCASE("duplicate player ids")
    {
        auto p1 = sign(shares[0], as_span(msg));
        auto p2 = sign(shares[0], as_span(msg));
        auto p3 = sign(shares[1], as_span(msg));

        std::vector<PartialSignature> partials { p1, p2, p3 };
        CHECK_FALSE(validate(params, as_span(msg), partials));
    }

    SUBCASE("invalid player id")
    {
        auto ps = sign(shares[0], as_span(msg));
        ps.player_id = params.total_players + 1;

        CAPTURE(ps.player_id);
        CHECK_FALSE(validate(params, as_span(msg), std::span { &ps, 1 }));
    }

    SUBCASE("wrong message")
    {
        auto ps = sign(shares[0], as_span(msg));
        CHECK_FALSE(verify_share(params, ps, as_span("WrongMessage")));
    }
}

} // namespace Honey::Crypto::Threshold::Sig

#endif // DOCTEST_CONFIG_DISABLE
