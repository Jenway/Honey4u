#include <gtest/gtest.h>
#include <string>

#include "crypto/common.hpp"
#include "crypto/ecdsa.hpp"

using namespace Honey::Crypto;
using namespace Honey::Crypto::Ecdsa;

class EcdsaTest : public ::testing::Test {
protected:
    Context ctx;

    const PrivateKey sample_priv_key_ = Utils::make_bytes<32>({ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 });

    const std::string sample_msg_str_ = "this is a test message for signing";
    BytesSpan sample_msg_ = as_span(sample_msg_str_);
};

TEST_F(EcdsaTest, SignAndVerifySuccess)
{
    auto pub_key_res = get_public_key(ctx, sample_priv_key_);
    ASSERT_TRUE(pub_key_res.has_value());
    const auto& pub_key = *pub_key_res;

    auto signature_res = sign(ctx, sample_priv_key_, sample_msg_);
    ASSERT_TRUE(signature_res.has_value());
    const auto& signature = *signature_res;

    bool is_valid = verify(ctx, pub_key, sample_msg_, signature);
    ASSERT_TRUE(is_valid);
}

TEST_F(EcdsaTest, VerifyFailsWithWrongPublicKey)
{
    PrivateKey wrong_priv_key = sample_priv_key_;
    wrong_priv_key[0] ^= std::byte(0xFF);

    auto wrong_pub_key = *get_public_key(ctx, wrong_priv_key);
    auto signature = sign(ctx, sample_priv_key_, sample_msg_).value();

    bool is_valid = verify(ctx, wrong_pub_key, sample_msg_, signature);
    ASSERT_FALSE(is_valid);
}

TEST_F(EcdsaTest, VerifyFailsWithTamperedMessage)
{
    auto pub_key = *get_public_key(ctx, sample_priv_key_);
    auto signature = sign(ctx, sample_priv_key_, sample_msg_).value();

    auto tampered_msg = as_span(sample_msg_str_ + "!");

    bool is_valid = verify(ctx, pub_key, tampered_msg, signature);
    ASSERT_FALSE(is_valid);
}

TEST_F(EcdsaTest, VerifyFailsWithTamperedSignature)
{
    auto pub_key = *get_public_key(ctx, sample_priv_key_);
    auto signature = sign(ctx, sample_priv_key_, sample_msg_).value();

    Signature tampered_signature = signature;
    tampered_signature[10] ^= Byte(0xFF);

    bool is_valid = verify(ctx, pub_key, sample_msg_, tampered_signature);
    ASSERT_FALSE(is_valid);
}

TEST_F(EcdsaTest, GetPublicKeyFailsWithInvalidPrivateKey)
{
    PrivateKey zero_priv_key {};
    auto pub_key_res = get_public_key(ctx, zero_priv_key);
    ASSERT_FALSE(pub_key_res.has_value());
}

TEST_F(EcdsaTest, SignFailsWithInvalidPrivateKey)
{
    PrivateKey zero_priv_key {};
    auto signature_res = sign(ctx, zero_priv_key, sample_msg_);
    ASSERT_FALSE(signature_res.has_value());
}
