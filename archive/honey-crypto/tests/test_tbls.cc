#include <gtest/gtest.h>
#include <iostream>
#include <string>
#include <vector>

#include "crypto/tbls.hpp"

using namespace blst;

TEST(TBLS_Test, EndToEndFlow)
{
    constexpr int N = 10;
    constexpr int K = 5;

    auto result = TBLS::dealer(N, K);
    ASSERT_TRUE(result.has_value()) << "Dealer setup failed: " << result.error();

    const auto [pk, sks] = std::move(result.value());

    EXPECT_EQ(pk.l, N);
    EXPECT_EQ(pk.k, K);
    EXPECT_EQ(sks.size(), N);

    std::string msg = "HoneyBadger-GTest";
    std::vector<int> signers = { 1, 2, 3, 4, 5 };
    std::vector<blst::P1> shares;

    for (int id : signers) {
        auto sig = TBLS::sign_share(sks[id - 1], msg);

        // 验证签名份额
        auto verify_result = TBLS::verify_share(pk, id, msg, sig);
        EXPECT_TRUE(verify_result) << "Share verification failed for signer " << id
                                   << ": " << verify_result.error().message();
        shares.push_back(sig);
    }

    // 3. 组合签名份额
    ASSERT_EQ(shares.size(), K);
    auto combined_result = TBLS::combine_shares(pk, signers, shares);

    ASSERT_TRUE(combined_result.has_value())
        << "Combine shares failed: " << combined_result.error().message();

    blst::P1 combined_sig = std::move(combined_result.value());

    auto master_verify_result = TBLS::verify_signature(pk, msg, combined_sig);
    EXPECT_TRUE(master_verify_result)
        << "Master signature verification failed: "
        << master_verify_result.error().message();

    byte buf[48];
    combined_sig.compress(buf);
}

TEST(TBLS_Test, NotEnoughShares)
{
    constexpr int N = 10;
    constexpr int K = 5;

    auto result = TBLS::dealer(N, K);
    ASSERT_TRUE(result.has_value()) << "Dealer setup failed";

    const auto [pk, sks] = std::move(result.value());

    std::string msg = "FailTest";
    std::vector<int> signers = { 1, 2 };
    std::vector<blst::P1> shares;

    for (int id : signers) {
        shares.push_back(TBLS::sign_share(sks[id - 1], msg));
    }

    auto combined_result = TBLS::combine_shares(pk, signers, shares);

    EXPECT_FALSE(combined_result.has_value())
        << "Combine should fail with insufficient shares";

    if (!combined_result.has_value()) {
        std::cout << "Expected error: " << combined_result.error().message() << std::endl;
    }
}

TEST(TBLS_Test, InvalidShareVerification)
{
    constexpr int N = 10;
    constexpr int K = 5;

    auto result = TBLS::dealer(N, K);
    ASSERT_TRUE(result.has_value());

    const auto [pk, sks] = std::move(result.value());

    std::string msg = "TestMessage";
    std::string wrong_msg = "WrongMessage";

    auto sig = TBLS::sign_share(sks[0], msg);

    auto verify_result = TBLS::verify_share(pk, 1, wrong_msg, sig);

    EXPECT_FALSE(verify_result)
        << "Should fail when verifying with wrong message";
}
