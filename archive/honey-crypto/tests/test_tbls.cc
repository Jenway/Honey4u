#include <gtest/gtest.h>
#include <iostream>
#include <string>
#include <vector>

#include "crypto/threshold/tbls.hpp"

using namespace Honey::Crypto;
using namespace Honey::Crypto::Tbls;

TEST(TBLS_Test, EndToEndFlow)
{
    constexpr int N = 10;
    constexpr int K = 5;

    auto result = Honey::Crypto::Tbls::generate_keys(N, K);
    ASSERT_TRUE(result.has_value()) << "Key generation failed";

    const auto& kg = result.value();
    const auto& params = kg.public_params;
    const auto& shares = kg.private_shares;

    EXPECT_EQ(params.total_players, N);
    EXPECT_EQ(params.threshold, K);
    EXPECT_EQ(shares.size(), N);

    std::string msg = "HoneyBadger-GTest";

    std::vector<Honey::Crypto::Tbls::PartialSignature> partials;

    for (int id = 1; id <= K; ++id) {
        auto ps = Honey::Crypto::Tbls::sign_share(shares[id - 1], as_span(msg));

        auto verify = Honey::Crypto::Tbls::verify_share(
            params, ps.value, as_span(msg), ps.player_id);

        EXPECT_TRUE(verify)
            << "Partial verification failed for player " << id;

        partials.push_back(std::move(ps));
    }

    ASSERT_EQ(partials.size(), K);

    auto combined = Honey::Crypto::Tbls::combine_partial_signatures(
        params, partials);

    ASSERT_TRUE(combined.has_value())
        << "Combine failed";

    auto verify_master = Honey::Crypto::Tbls::verify_signature(
        params, as_span(msg), combined.value());

    EXPECT_TRUE(verify_master)
        << "Master signature verification failed";
}
TEST(TBLS_Test, NotEnoughShares)
{
    constexpr int N = 10;
    constexpr int K = 5;

    auto result = Honey::Crypto::Tbls::generate_keys(N, K);
    ASSERT_TRUE(result.has_value());

    const auto& params = result->public_params;
    const auto& shares = result->private_shares;

    std::string msg = "FailTest";

    std::vector<Honey::Crypto::Tbls::PartialSignature> partials;

    for (int id = 1; id <= 2; ++id) {
        partials.push_back(
            Honey::Crypto::Tbls::sign_share(shares[id - 1], as_span(msg)));
    }

    auto combined = Honey::Crypto::Tbls::combine_partial_signatures(
        params, partials);

    EXPECT_FALSE(combined.has_value());
    EXPECT_EQ(combined.error(), Honey::Crypto::Error::NotEnoughShares);
}

TEST(TBLS_Test, InvalidShareVerification)
{
    constexpr int N = 10;
    constexpr int K = 5;

    auto result = Honey::Crypto::Tbls::generate_keys(N, K);
    ASSERT_TRUE(result.has_value());

    const auto& params = result->public_params;
    const auto& shares = result->private_shares;

    std::string msg = "CorrectMessage";
    std::string wrong_msg = "WrongMessage";

    auto ps = Honey::Crypto::Tbls::sign_share(shares[0], as_span(msg));

    auto verify = Honey::Crypto::Tbls::verify_share(params,ps.value, as_span(wrong_msg),ps.player_id);

    EXPECT_FALSE(verify);
    EXPECT_EQ(verify.error(), Error::ShareVerificationFailed);
}

TEST(TBLS_Test, DuplicatePlayerIds)
{
    constexpr int N = 5;
    constexpr int K = 3;

    auto result = Honey::Crypto::Tbls::generate_keys(N, K);
    ASSERT_TRUE(result.has_value());

    const auto& params = result->public_params;
    const auto& shares = result->private_shares;

    std::string msg = "DupTest";

    auto p1 = Honey::Crypto::Tbls::sign_share(shares[0], as_span(msg));
    auto p2 = Honey::Crypto::Tbls::sign_share(shares[0], as_span(msg));
    auto p3 = Honey::Crypto::Tbls::sign_share(shares[1], as_span(msg));

    std::vector<Honey::Crypto::Tbls::PartialSignature> partials {
        p1, p2, p3
    };

    auto combined = Honey::Crypto::Tbls::combine_partial_signatures(
        params, partials);

    EXPECT_FALSE(combined.has_value());
}

TEST(TBLS_Test, InvalidPlayerId)
{
    constexpr int N = 5;
    constexpr int K = 3;

    auto result = Honey::Crypto::Tbls::generate_keys(N, K);
    ASSERT_TRUE(result.has_value());

    auto params = result->public_params;
    auto shares = result->private_shares;

    std::string msg = "BadId";

    auto ps = Honey::Crypto::Tbls::sign_share(shares[0], as_span(msg));
    ps.player_id = N + 1;

    std::vector<Honey::Crypto::Tbls::PartialSignature> partials { ps };

    auto combined = Honey::Crypto::Tbls::combine_partial_signatures(
        params, partials);

    EXPECT_FALSE(combined.has_value());
    EXPECT_EQ(combined.error(), Error::InvalidShareID);
}
