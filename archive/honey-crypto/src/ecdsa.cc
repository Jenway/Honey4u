#include "crypto/ecdsa.hpp"
#include "crypto/common.hpp"
#include <cstddef>

namespace Honey::Crypto::Ecdsa {

auto sign(const Context& ctx,
    const PrivateKey& priv_key,
    BytesSpan msg) -> std::expected<Signature, std::string>
{
    auto msg_hash = Utils::sha256(msg);

    secp256k1_ecdsa_signature sig_struct;

    if (!secp256k1_ecdsa_sign(ctx.get(), &sig_struct, msg_hash.data(), priv_key.data(), NULL, NULL)) {
        return std::unexpected("Failed to sign message");
    }

    Signature output;
    secp256k1_ecdsa_signature_serialize_compact(ctx.get(), output.data(), &sig_struct);

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
    if (!secp256k1_ec_pubkey_parse(ctx.get(), &pubkey_struct, pub_key.data(), pub_key.size())) {
        return false;
    }

    secp256k1_ecdsa_signature sig_struct;
    if (!secp256k1_ecdsa_signature_parse_compact(ctx.get(), &sig_struct, sig.data())) {
        return false;
    }

    return secp256k1_ecdsa_verify(ctx.get(), &sig_struct, msg_hash.data(), &pubkey_struct) == 1;
}

auto get_public_key(const Context& ctx,
    const PrivateKey& priv_key) -> std::expected<PublicKey, std::string>
{
    secp256k1_pubkey pubkey_struct;
    if (!secp256k1_ec_pubkey_create(ctx.get(), &pubkey_struct, priv_key.data())) {
        return std::unexpected("Failed to create public key from private key");
    }

    PublicKey output;
    size_t output_len = output.size();

    secp256k1_ec_pubkey_serialize(ctx.get(), output.data(), &output_len, &pubkey_struct, SECP256K1_EC_COMPRESSED);

    return output;
}

} // namespace Honey::Crypto
