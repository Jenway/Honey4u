#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "crypto/threshold/tpke.hpp"

using namespace Honey::Crypto;
using namespace Honey::Crypto::Tpke;

class TpkeTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        auto key_set_result = generate_keys(N, K);
        ASSERT_TRUE(key_set_result.has_value());
        key_set_ = *key_set_result;
    }

    static std::vector<Byte> string_to_bytes(const std::string& str)
    {
        auto view = str | std::views::transform([](char c) { return static_cast<Byte>(c); });
        return { view.begin(), view.end() };
    }

    const int N = 5;
    const int K = 3;

    std::optional<TpkeKeySet> key_set_;
    Aes::Context ctx;
};

TEST_F(TpkeTest, HybridEncryptionDecryptionFlow)
{
    // 1. Encrypt
    const std::string secret_msg = "HoneyBadger BFT is robust!";
    HybridCiphertext hc = Hybrid::encrypt(ctx,key_set_->public_params, string_to_bytes(secret_msg));

    // A basic sanity check on the ciphertext
    EXPECT_FALSE(hc.data_ciphertext.empty());

    // 2. Generate Decryption Shares
    // CHANGE: The new API expects a vector of PartialDecryption structs.
    std::vector<PartialDecryption> decryption_shares;
    const std::vector<int> decryptor_ids = { 1, 3, 5 }; // Choose K decryptors

    for (int id : decryptor_ids) {
        // Get the correct private key share (id-1 for 0-based index)
        const auto& private_share = key_set_->private_shares[id - 1];

        // Generate the decryption share (a P1 point)
        DecryptionShare share_value = decrypt_share(private_share, hc.key_ciphertext);

        // Create the struct that combines the ID and the share value
        PartialDecryption partial_decryption = { .player_id = id, .value = share_value };

        // It's good practice to verify the share before using it
        bool is_share_valid = verify_share(key_set_->public_params, partial_decryption, hc.key_ciphertext);
        EXPECT_TRUE(is_share_valid) << "Decryption share verification failed for ID: " << id;

        if (is_share_valid) {
            decryption_shares.push_back(partial_decryption);
        }
    }

    ASSERT_EQ(decryption_shares.size(), K);

    // 3. Combine & Decrypt
    // CHANGE: Call the new, streamlined Hybrid::decrypt function.
    auto decrypted_result = Hybrid::decrypt(ctx,key_set_->public_params, hc, decryption_shares);

    // 4. Verify the result
    // CHANGE: Check the std::expected for a value.
    ASSERT_TRUE(decrypted_result.has_value());
    EXPECT_EQ(*decrypted_result, string_to_bytes(secret_msg)) << "Decrypted message does not match original";
}

// Test case for decryption failure with a bad share
TEST_F(TpkeTest, DecryptionFailsWithBadShare)
{
    // 1. Encrypt
    const std::string secret_msg = "This should not be decrypted";
    HybridCiphertext hc = Hybrid::encrypt(ctx,key_set_->public_params, string_to_bytes(secret_msg));

    // 2. Generate K shares, but one is intentionally bad
    std::vector<PartialDecryption> shares;
    // Add two correct shares
    shares.push_back({ .player_id = 1, .value = decrypt_share(key_set_->private_shares[0], hc.key_ciphertext) });
    shares.push_back({ .player_id = 2, .value = decrypt_share(key_set_->private_shares[1], hc.key_ciphertext) });

    // Create a junk share for player 3
    P1 bad_share_value = P1::generator(); // A point that is not a valid share
    PartialDecryption bad_partial_decryption = { .player_id = 3, .value = bad_share_value };
    shares.push_back(bad_partial_decryption);

    // We expect the verification for this specific share to fail
    EXPECT_FALSE(verify_share(key_set_->public_params, bad_partial_decryption, hc.key_ciphertext));

    // 3. Attempt to decrypt with the corrupted set of shares
    auto decrypted_result = Hybrid::decrypt(ctx,key_set_->public_params, hc, shares);

    // 4. Verify that decryption failed
    // CHANGE: The new API returns an empty std::expected, which is a much cleaner
    // and more reliable way to signal failure than catching exceptions or checking for garbage.
    EXPECT_FALSE(decrypted_result.has_value());
}

TEST_F(TpkeTest, DecryptionFailsWithNotEnoughShares)
{
    const std::string secret_msg = "Fewer than K shares";
    HybridCiphertext hc = Hybrid::encrypt(ctx,key_set_->public_params, string_to_bytes(secret_msg));

    // Generate only K-1 shares
    std::vector<PartialDecryption> shares;
    shares.push_back({ .player_id = 1, .value = decrypt_share(key_set_->private_shares[0], hc.key_ciphertext) });
    shares.push_back({ .player_id = 2, .value = decrypt_share(key_set_->private_shares[1], hc.key_ciphertext) });

    ASSERT_EQ(shares.size(), K - 1);

    // Attempt to decrypt
    auto decrypted_result = Hybrid::decrypt(ctx,key_set_->public_params, hc, shares);

    // Expect failure
    EXPECT_FALSE(decrypted_result.has_value());
    // You could even check for the specific error code if your function returns it
    // EXPECT_EQ(decrypted_result.error(), std::errc::message_size);
}

TEST_F(TpkeTest, DecryptionFailsWithDuplicateShare)
{
    const std::string secret_msg = "Duplicate shares are invalid";
    HybridCiphertext hc = Hybrid::encrypt(ctx,key_set_->public_params, string_to_bytes(secret_msg));

    std::vector<PartialDecryption> shares;
    // Add share from player 1
    shares.push_back({ .player_id = 1, .value = decrypt_share(key_set_->private_shares[0], hc.key_ciphertext) });
    // Add share from player 2
    shares.push_back({ .player_id = 2, .value = decrypt_share(key_set_->private_shares[1], hc.key_ciphertext) });
    // Add share from player 1 AGAIN
    shares.push_back({ .player_id = 1, .value = decrypt_share(key_set_->private_shares[0], hc.key_ciphertext) });

    ASSERT_EQ(shares.size(), K);

    auto decrypted_result = Hybrid::decrypt(ctx,key_set_->public_params, hc, shares);
    EXPECT_FALSE(decrypted_result.has_value());
}

// // You can define a new test fixture that inherits from TpkeTest and testing::WithParamInterface
// class TpkeParameterizedTest : public TpkeTest, public ::testing::WithParamInterface<std::pair<int, int>> {
// protected:
//     void SetUp() override
//     {
//         N = GetParam().first;
//         K = GetParam().second;
//         TpkeTest::SetUp(); // Call the base class SetUp
//     }
// };

// TEST_P(TpkeParameterizedTest, FullFlowWithVariousConfigurations)
// {
//     // This entire test body is the same as the original HybridEncryptionDecryptionFlow test.
//     // GTest will run it for every (N, K) pair you provide below.
//     // ... (copy paste the logic from the first test) ...
// }

// // Instantiate the test suite with different (N, K) values
// INSTANTIATE_TEST_SUITE_P(
//     TpkeConfigurations,
//     TpkeParameterizedTest,
//     ::testing::Values(
//         std::make_pair(3, 2),
//         std::make_pair(5, 3),
//         std::make_pair(5, 5), // Test the case where K=N
//         std::make_pair(10, 7)));