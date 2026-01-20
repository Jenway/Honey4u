#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "crypto/threshold/tpke.hpp"

namespace Honey::Crypto::Tpke {

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

public:
    const int N = 5;
    const int K = 3;

    std::optional<TpkeKeySet> key_set_;
    Aes::Context ctx;
};

TEST_F(TpkeTest, HybridEncryptionDecryptionFlow)
{
    const std::string secret_msg = "HoneyBadger BFT is robust!";
    HybridCiphertext hc = encrypt(ctx, key_set_->public_params, string_to_bytes(secret_msg));

    EXPECT_FALSE(hc.data_ciphertext.empty());

    std::vector<PartialDecryption> decryption_shares;
    const std::vector<int> decryptor_ids = { 1, 3, 5 }; // Choose K decryptors

    for (int id : decryptor_ids) {
        const auto& private_share = key_set_->private_shares[id - 1];

        DecryptionShare share_value = detail::decrypt_share(private_share, hc.key_ciphertext);

        PartialDecryption partial_decryption = { .player_id = id, .value = share_value };

        bool is_share_valid = detail::verify_share(key_set_->public_params, partial_decryption, hc.key_ciphertext);
        EXPECT_TRUE(is_share_valid) << "Decryption share verification failed for ID: " << id;

        if (is_share_valid) {
            decryption_shares.push_back(partial_decryption);
        }
    }

    ASSERT_EQ(decryption_shares.size(), K);

    auto decrypted_result = decrypt(ctx, key_set_->public_params, hc, decryption_shares);

    ASSERT_TRUE(decrypted_result.has_value());
    EXPECT_EQ(*decrypted_result, string_to_bytes(secret_msg)) << "Decrypted message does not match original";
}

TEST_F(TpkeTest, DecryptionFailsWithBadShare)
{
    const std::string secret_msg = "This should not be decrypted";
    HybridCiphertext hc = encrypt(ctx, key_set_->public_params, string_to_bytes(secret_msg));

    std::vector<PartialDecryption> shares;

    shares.push_back({ .player_id = 1, .value = detail::decrypt_share(key_set_->private_shares[0], hc.key_ciphertext) });
    shares.push_back({ .player_id = 2, .value = detail::decrypt_share(key_set_->private_shares[1], hc.key_ciphertext) });
    P1 bad_share_value = P1::generator(); // A point that is not a valid share
    PartialDecryption bad_partial_decryption = { .player_id = 3, .value = bad_share_value };
    shares.push_back(bad_partial_decryption);

    EXPECT_FALSE(detail::verify_share(key_set_->public_params, bad_partial_decryption, hc.key_ciphertext));

    auto decrypted_result = decrypt(ctx, key_set_->public_params, hc, shares);

    EXPECT_FALSE(decrypted_result.has_value());
}

TEST_F(TpkeTest, DecryptionFailsWithNotEnoughShares)
{
    const std::string secret_msg = "Fewer than K shares";
    HybridCiphertext hc = encrypt(ctx, key_set_->public_params, string_to_bytes(secret_msg));

    // Generate only K-1 shares
    std::vector<PartialDecryption> shares;
    shares.push_back({ .player_id = 1, .value = detail::decrypt_share(key_set_->private_shares[0], hc.key_ciphertext) });
    shares.push_back({ .player_id = 2, .value = detail::decrypt_share(key_set_->private_shares[1], hc.key_ciphertext) });

    ASSERT_EQ(shares.size(), K - 1);

    auto decrypted_result = decrypt(ctx, key_set_->public_params, hc, shares);

    EXPECT_FALSE(decrypted_result.has_value());
}

TEST_F(TpkeTest, DecryptionFailsWithDuplicateShare)
{
    const std::string secret_msg = "Duplicate shares are invalid";
    HybridCiphertext hc = encrypt(ctx, key_set_->public_params, string_to_bytes(secret_msg));

    std::vector<PartialDecryption> shares;
    shares.push_back({ .player_id = 1, .value = detail::decrypt_share(key_set_->private_shares[0], hc.key_ciphertext) });
    shares.push_back({ .player_id = 2, .value = detail::decrypt_share(key_set_->private_shares[1], hc.key_ciphertext) });
    shares.push_back({ .player_id = 1, .value = detail::decrypt_share(key_set_->private_shares[0], hc.key_ciphertext) });

    ASSERT_EQ(shares.size(), K);

    auto decrypted_result = decrypt(ctx, key_set_->public_params, hc, shares);
    EXPECT_FALSE(decrypted_result.has_value());
}

} // namespace Honey::Crypto::Tpke
