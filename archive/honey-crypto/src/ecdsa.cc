#include "crypto/ecdsa.hpp"
#include "hash.hpp"
#include "utils.hpp"
#include <cstddef>
#include <secp256k1.h>
#include <system_error>
#include <utility>

namespace Honey::Crypto::Ecdsa {
constexpr auto SECP256K1_INIT_FLAG = SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY;

Context::Context()
    : ptr_(secp256k1_context_create(SECP256K1_INIT_FLAG))
{
}

Context::~Context()
{
    if (ptr_ != nullptr)
        secp256k1_context_destroy(ptr_);
}

Context::Context(Context&& other) noexcept
    : ptr_(std::exchange(other.ptr_, nullptr))
{
}

Context& Context::operator=(Context&& other) noexcept
{
    if (this != &other) {
        if (ptr_ != nullptr)
            secp256k1_context_destroy(ptr_);
        ptr_ = std::exchange(other.ptr_, nullptr);
    }
    return *this;
}

auto sign(const Context& ctx,
    const PrivateKey& priv_key,
    BytesSpan msg) -> std::expected<Signature, std::error_code>
{
    auto msg_hash = Utils::sha256(msg);

    secp256k1_ecdsa_signature sig_struct;

    if (secp256k1_ecdsa_sign(
            ctx.get(),
            &sig_struct,
            u8ptr(msg_hash.data()),
            u8ptr(priv_key.data()),
            nullptr,
            nullptr)
        == 0) {
        return std::unexpected(std::make_error_code(std::errc::protocol_error));
    }

    Signature output;
    secp256k1_ecdsa_signature_serialize_compact(
        ctx.get(),
        u8ptr(output.data()),
        &sig_struct);

    return output;
}

bool verify(
    const Context& ctx,
    const PublicKey& pub_key,
    BytesSpan msg,
    const Signature& sig)
{
    auto msg_hash = Utils::sha256(msg);

    secp256k1_pubkey pubkey_struct;
    if (secp256k1_ec_pubkey_parse(ctx.get(), &pubkey_struct, u8ptr(pub_key.data()), pub_key.size()) == 0) {
        return false;
    }

    secp256k1_ecdsa_signature sig_struct;
    if (secp256k1_ecdsa_signature_parse_compact(ctx.get(), &sig_struct, u8ptr(sig.data())) == 0) {
        return false;
    }

    return secp256k1_ecdsa_verify(
               ctx.get(),
               &sig_struct,
               u8ptr(msg_hash.data()),
               &pubkey_struct)
        == 1;
}

auto get_public_key(const Context& ctx,
    const PrivateKey& priv_key) -> std::expected<PublicKey, std::error_code>
{
    secp256k1_pubkey pubkey_struct;
    if (secp256k1_ec_pubkey_create(ctx.get(), &pubkey_struct, u8ptr(priv_key.data())) == 0) {
        return std::unexpected(std::make_error_code(std::errc::protocol_error));
    }

    PublicKey output;
    size_t output_len = output.size();

    secp256k1_ec_pubkey_serialize(ctx.get(), u8ptr(output.data()), &output_len, &pubkey_struct, SECP256K1_EC_COMPRESSED);

    return output;
}

} // namespace Honey::Crypto::Ecdsa

#include <doctest/doctest.h>
#include <string>

#include "crypto/ecdsa.hpp"
#include "crypto/types.hpp"

namespace Honey::Crypto::Ecdsa {

struct EcdsaTest {
    Context ctx;

    const PrivateKey sample_priv_key_ = Honey::Crypto::Utils::make_bytes<32>({ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 });

    const std::string sample_msg_str_ = "this is a test message for signing";
    BytesSpan sample_msg_ = as_span(sample_msg_str_);
};

TEST_CASE_FIXTURE(EcdsaTest, "EcdsaTest.SignAndVerifySuccess")
{
    auto pub_key_res = get_public_key(ctx, sample_priv_key_);
    REQUIRE(pub_key_res.has_value());
    const auto& pub_key = *pub_key_res;

    auto signature_res = sign(ctx, sample_priv_key_, sample_msg_);
    REQUIRE(signature_res.has_value());
    const auto& signature = *signature_res;

    bool is_valid = verify(ctx, pub_key, sample_msg_, signature);
    REQUIRE(is_valid);
}

TEST_CASE_FIXTURE(EcdsaTest, "EcdsaTest.VerifyFailsWithWrongPublicKey")
{
    PrivateKey wrong_priv_key = sample_priv_key_;
    wrong_priv_key[0] ^= std::byte(0xFF);

    auto wrong_pub_key = *get_public_key(ctx, wrong_priv_key);
    auto signature = sign(ctx, sample_priv_key_, sample_msg_).value();

    bool is_valid = verify(ctx, wrong_pub_key, sample_msg_, signature);
    REQUIRE_FALSE(is_valid);
}

TEST_CASE_FIXTURE(EcdsaTest, "EcdsaTest.VerifyFailsWithTamperedMessage")
{
    auto pub_key = *get_public_key(ctx, sample_priv_key_);
    auto signature = sign(ctx, sample_priv_key_, sample_msg_).value();

    auto tampered_msg = as_span(sample_msg_str_ + "!");

    bool is_valid = verify(ctx, pub_key, tampered_msg, signature);
    REQUIRE_FALSE(is_valid);
}

TEST_CASE_FIXTURE(EcdsaTest, "EcdsaTest.VerifyFailsWithTamperedSignature")
{
    auto pub_key = *get_public_key(ctx, sample_priv_key_);
    auto signature = sign(ctx, sample_priv_key_, sample_msg_).value();

    Signature tampered_signature = signature;
    tampered_signature[10] ^= Byte(0xFF);

    bool is_valid = verify(ctx, pub_key, sample_msg_, tampered_signature);
    REQUIRE_FALSE(is_valid);
}

TEST_CASE_FIXTURE(EcdsaTest, "EcdsaTest.GetPublicKeyFailsWithInvalidPrivateKey")
{
    PrivateKey zero_priv_key {};
    auto pub_key_res = get_public_key(ctx, zero_priv_key);
    REQUIRE_FALSE(pub_key_res.has_value());
}

TEST_CASE_FIXTURE(EcdsaTest, "EcdsaTest.SignFailsWithInvalidPrivateKey")
{
    PrivateKey zero_priv_key {};
    auto signature_res = sign(ctx, zero_priv_key, sample_msg_);
    REQUIRE_FALSE(signature_res.has_value());
}

} // namespace Honey::Crypto::Ecdsa
