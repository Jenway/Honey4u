#include "crypto/ecdsa.hpp"
#include "crypto/common.hpp"
#include <cstddef>
#include <secp256k1.h>
#include <system_error>
#include <utility>

namespace Honey::Crypto::Ecdsa {
using Crypto::u8ptr;
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
