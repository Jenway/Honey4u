#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "crypto/ecdsa.h"

using namespace Honey::Crypto;

class EcdsaTest : public ::testing::Test {
protected:
    Context ctx = create_context();

    const std::array<uint8_t, 32> sample_priv_key_ = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88
    };

    const std::string sample_msg_ = "this is a test message for signing";
};

TEST_F(EcdsaTest, SignAndVerifySuccess) {
    auto pub_key = *Secp256k1::get_public_key(ctx, sample_priv_key_);
    ASSERT_EQ(pub_key.size(), 33);

    auto signature_or_error = Secp256k1::sign(ctx, sample_priv_key_, sample_msg_);
    ASSERT_TRUE(signature_or_error.has_value());
    auto signature = signature_or_error.value();
    ASSERT_EQ(signature.size(), 64);

    bool is_valid = Secp256k1::verify(ctx, pub_key, sample_msg_, signature);
    ASSERT_TRUE(is_valid);
}

TEST_F(EcdsaTest, VerifyFailsWithWrongPublicKey) {
    std::array<uint8_t, 32> wrong_priv_key = sample_priv_key_;
    wrong_priv_key[0] ^= 0xFF; 

    auto correct_pub_key = *Secp256k1::get_public_key(ctx, sample_priv_key_);
    auto wrong_pub_key = *Secp256k1::get_public_key(ctx, wrong_priv_key);
    
    auto signature = Secp256k1::sign(ctx, sample_priv_key_, sample_msg_).value();

    bool is_valid = Secp256k1::verify(ctx, wrong_pub_key, sample_msg_, signature);
    ASSERT_FALSE(is_valid);
}

TEST_F(EcdsaTest, VerifyFailsWithTamperedMessage) {
    auto pub_key = *Secp256k1::get_public_key(ctx, sample_priv_key_);
    auto signature = Secp256k1::sign(ctx, sample_priv_key_, sample_msg_).value();

    std::string tampered_msg = sample_msg_ + "!";

    bool is_valid = Secp256k1::verify(ctx, pub_key, tampered_msg, signature);
    ASSERT_FALSE(is_valid);
}

TEST_F(EcdsaTest, VerifyFailsWithTamperedSignature) {
    auto pub_key = *Secp256k1::get_public_key(ctx, sample_priv_key_);
    auto signature = Secp256k1::sign(ctx, sample_priv_key_, sample_msg_).value();

    signature[10] ^= 0xFF;

    bool is_valid = Secp256k1::verify(ctx, pub_key, sample_msg_, signature);
    ASSERT_FALSE(is_valid);
}
