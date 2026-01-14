#pragma once

#include <array>
#include <expected>
#include <memory>
#include <string>
#include <vector>

#include <secp256k1.h>

namespace Honey::Crypto {

struct Secp256k1Deleter {
    void operator()(secp256k1_context* ctx) const
    {
        if (ctx) {
            secp256k1_context_destroy(ctx);
        }
    }
};

using Context = std::unique_ptr<secp256k1_context, Secp256k1Deleter>;

inline Context create_context()
{
    return Context(secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY));
}

namespace Secp256k1 {
    auto sign(const Context& ctx, const std::array<uint8_t, 32>& priv_key, const std::string& msg) -> std::expected<std::vector<uint8_t>, std::string>;

    bool verify(const Context& ctx, const std::vector<uint8_t>& pub_key_raw, const std::string& msg, const std::vector<uint8_t>& sig_compact);

    auto get_public_key(const Context& ctx, const std::array<uint8_t, 32>& priv_key) -> std::expected<std::vector<uint8_t>, std::string>;
};

} // namespace Honey::Crypto