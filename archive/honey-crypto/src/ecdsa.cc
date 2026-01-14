#include "crypto/ecdsa.h"

#include <openssl/sha.h>

namespace Honey::Crypto {

namespace {
    inline std::array<uint8_t, 32> sha256(const std::string& data)
    {
        std::array<uint8_t, 32> hash;
        SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(), hash.data());
        return hash;
    }
}

auto Secp256k1::sign(const Context& ctx,
    const std::array<uint8_t, 32>& priv_key,
    const std::string& msg) -> std::expected<std::vector<uint8_t>, std::string>
{
    auto msg_hash = sha256(msg);
    secp256k1_ecdsa_signature sig;

    if (!secp256k1_ecdsa_sign(ctx.get(), &sig, msg_hash.data(), priv_key.data(), NULL, NULL)) {
        return std::unexpected("Failed to sign message");
    }

    std::vector<uint8_t> output(64);
    secp256k1_ecdsa_signature_serialize_compact(ctx.get(), output.data(), &sig);
    return output;
}

bool Secp256k1::verify(const Context& ctx,
    const std::vector<uint8_t>& pub_key_raw,
    const std::string& msg,
    const std::vector<uint8_t>& sig_compact)
{
    auto msg_hash = sha256(msg);
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_parse(ctx.get(), &pubkey, pub_key_raw.data(), pub_key_raw.size())) {
        return false;
    }

    secp256k1_ecdsa_signature sig;
    if (!secp256k1_ecdsa_signature_parse_compact(ctx.get(), &sig, sig_compact.data())) {
        return false;
    }

    return secp256k1_ecdsa_verify(ctx.get(), &sig, msg_hash.data(), &pubkey) == 1;
}

auto Secp256k1::get_public_key(const Context& ctx,
    const std::array<uint8_t, 32>& priv_key) -> std::expected<std::vector<uint8_t>, std::string>
{
    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx.get(), &pubkey, priv_key.data())) {
        return std::unexpected("Failed to create public key from private key");
    }

    std::vector<uint8_t> output(33);
    size_t output_len = 33;
    secp256k1_ec_pubkey_serialize(ctx.get(), output.data(), &output_len, &pubkey, SECP256K1_EC_COMPRESSED);
    return output;
}

} // namespace Honey::Crypto
