#include "crypto/threshold/tpke.hpp"
#include "aes.hpp"
#include "blst/P1_Affine.hpp"
#include "blst/P2_Affine.hpp"
#include "blst/PT.hpp"
#include "blst/ops.hpp"
#include "crypto/blst/P1.hpp"
#include "crypto/blst/P2.hpp"
#include "crypto/blst/Scalar.hpp"
#include "crypto/error.hpp"
#include "impl_utils.hpp"
#include "threshold/key_gen.hpp"
#include "threshold/math.hpp"
#include "threshold/utils.hpp"
#include <array>
#include <cstring>
#include <expected>
#include <openssl/rand.h>
#include <span>
#include <stdexcept>
#include <system_error>
#include <vector>

namespace Honey::Crypto::Tpke {

struct Context::Impl {
    Aes::Context aes_ctx;
};

Context::Context()
    : pimpl_(std::make_unique<Impl>())
{
}
Context::~Context() = default;
Context::Context(Context&&) noexcept = default;
Context& Context::operator=(Context&&) noexcept = default;

namespace detail {
    Ciphertext encrypt_key(const TpkeVerificationParameters& public_params,
        std::span<const Byte, 32> symmetric_key)
    {
        auto random_scalar = *Scalar::random();

        P1 u = P1::generator();
        bls::ops::mult(u, random_scalar);

        P1 mask_point = public_params.master_public_key;
        bls::ops::mult(mask_point, random_scalar);
        auto mask = Utils::hashG(mask_point);

        std::vector<Byte> v = Utils::xor_bytes(
            { symmetric_key.begin(), symmetric_key.end() }, mask);

        P2 h = Utils::hashH(u, v);
        P2 w = h;
        bls::ops::mult(w, random_scalar);

        return { .u_component = u, .v_component = v, .w_component = w };
    }

    using P1_Affine = Crypto::bls::P1_Affine;
    using P2_Affine = Crypto::bls::P2_Affine;
    using PT = Crypto::bls::PT;

    bool verify_ciphertext(const Ciphertext& C)
    {
        // PT(P2, P1) -> MillerLoop(P2, P1)
        PT lhs(C.w_component, P1::generator());
        lhs.final_exp();

        PT rhs(Utils::hashH(C.u_component, C.v_component), C.u_component);
        rhs.final_exp();

        return lhs == rhs;
    }

    DecryptionShare decrypt_share(const TpkePrivateKeyShare& private_share,
        const Ciphertext& ciphertext)
    {
        DecryptionShare share_ui = ciphertext.u_component;
        bls::ops::mult(share_ui, private_share.secret);
        return share_ui;
    }

    bool verify_share(const TpkeVerificationParameters& public_params,
        const PartialDecryption& decryption,
        const Ciphertext& ciphertext)
    {
        int id = decryption.player_id;
        if (id < 1 || id > public_params.total_players)
            return false;

        auto ui_aff = P1_Affine::from_P1(decryption.value);
        auto g2_aff = P2_Affine::from_P2(P2::generator());
        auto u_aff = P1_Affine::from_P1(ciphertext.u_component);
        auto yi_aff = P2_Affine::from_P2(public_params.verification_vector[id - 1]);

        PT lhs(g2_aff, ui_aff);
        lhs.final_exp();
        PT rhs(yi_aff, u_aff);
        rhs.final_exp();

        return lhs == rhs;
    }
}

auto generate_keys(int players, int k) -> std::expected<TpkeKeySet, std::error_code>
{
    return Threshold::generate_keys<MasterPublicKey, VerificationKey>(players, k);
}

HybridCiphertext encrypt(Context& ctx, const TpkeVerificationParameters& public_params,
    BytesSpan plaintext)
{
    std::array<Byte, 32> session_key {};
    RAND_bytes(
        Honey::Crypto::impl::u8ptr(session_key.data()), session_key.size());

    Ciphertext key_ciphertext = detail::encrypt_key(public_params, session_key);

    std::vector<Byte> pt_bytes(plaintext.begin(), plaintext.end());
    std::vector<Byte> data_ciphertext = *Aes::encrypt(ctx.impl()->aes_ctx, { session_key.begin(), session_key.end() }, pt_bytes);

    return { .key_ciphertext = key_ciphertext, .data_ciphertext = data_ciphertext };
}
[[nodiscard]]
auto decrypt(Context& ctx, const TpkeVerificationParameters& public_params,
    const HybridCiphertext& ciphertext,
    std::span<const PartialDecryption> shares)
    -> std::expected<std::vector<Byte>, std::error_code>
{
    if (shares.size() < static_cast<size_t>(public_params.threshold)) {
        return std::unexpected(make_error_code(Crypto::Error::NotEnoughShares));
    }

    auto interpolation_result = Crypto::Math::interpolate_at_zero(shares);
    if (!interpolation_result) {
        return std::unexpected(interpolation_result.error());
    }
    const P1& recovered_point = *interpolation_result;

    Hash256 mask = Utils::hashG(recovered_point);

    std::vector<Byte> session_key = Utils::xor_bytes(
        ciphertext.key_ciphertext.v_component,
        mask);

    try {
        return Aes::decrypt(ctx.impl()->aes_ctx, session_key, ciphertext.data_ciphertext);
    } catch (const std::runtime_error& e) {
        return std::unexpected(make_error_code(Crypto::Error::OpenSSLError));
    }
}
} // namespace Honey::Crypto::Tpke
