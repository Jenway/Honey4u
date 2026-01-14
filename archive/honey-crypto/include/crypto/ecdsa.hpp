#pragma once

#include <array>
#include <expected>
#include <memory>
#include <string>

#include <secp256k1.h>

#include "common.hpp"

namespace Honey::Crypto::Ecdsa {

using PrivateKey = std::array<Byte, 32>;

using PublicKey = std::array<Byte, 33>;

using Signature = std::array<Byte, 64>;

struct Secp256k1Deleter {
    void operator()(secp256k1_context* ctx) const
    {
        if (ctx)
            secp256k1_context_destroy(ctx);
    }
};

using Context = std::unique_ptr<secp256k1_context, Secp256k1Deleter>;

inline Context create_context()
{
    return Context(secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY));
}
auto sign(const Context& ctx,
    const PrivateKey& priv_key,
    BytesSpan msg)
    -> std::expected<Signature, std::string>;

bool verify(const Context& ctx,
    const PublicKey& pub_key,
    BytesSpan msg,
    const Signature& sig);

auto get_public_key(const Context& ctx,
    const PrivateKey& priv_key)
    -> std::expected<PublicKey, std::string>;

} // namespace
