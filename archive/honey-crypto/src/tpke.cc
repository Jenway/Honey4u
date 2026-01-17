#include "crypto/threshold/tpke.hpp"
#include "crypto/blst/P1.hpp"
#include "crypto/blst/P2.hpp"
#include "crypto/blst/PT.hpp"
#include "crypto/blst/Scalar.hpp"
#include "crypto/common.hpp"
#include "crypto/threshold/math.hpp"
#include "crypto/threshold/utils.hpp"
#include <array>
#include <cstring>
#include <expected>
#include <openssl/rand.h>
#include <span>
#include <stdexcept>
#include <system_error>
#include <vector>

namespace Honey::Crypto::Tpke {

Ciphertext encrypt_key(const TpkeVerificationParameters& public_params,
    std::span<const Byte, 32> symmetric_key)
{
    auto random_scalar = *Scalar::random();

    P1 u = P1::generator();
    u.mult(random_scalar);

    P1 mask_point = public_params.master_public_key;
    mask_point.mult(random_scalar);
    auto mask = Utils::hashG(mask_point);

    std::vector<Byte> v = Utils::xor_bytes(
        { symmetric_key.begin(), symmetric_key.end() }, mask);

    P2 h = Utils::hashH(u, v);
    P2 w = h;
    w.mult(random_scalar);

    return { .u_component = u, .v_component = v, .w_component = w };
}

using P1_Affine = Crypto::bls::P1_Affine;
using P2_Affine = Crypto::bls::P2_Affine;
using PT = Crypto::bls::PT;

bool verify_ciphertext(const Ciphertext& C)
{
    // e(g1, W) == e(U, H)
    auto g1_aff = P1_Affine::from_P1(P1::generator());
    auto W_aff = P2_Affine::from_P2(C.w_component);

    auto U_aff = P1_Affine::from_P1(C.u_component);
    auto H_aff = P2_Affine::from_P2(Utils::hashH(C.u_component, C.v_component));

    // PT(P2, P1) -> MillerLoop(P2, P1)
    PT lhs(W_aff, g1_aff);
    lhs.final_exp();

    PT rhs(H_aff, U_aff);
    rhs.final_exp();

    return lhs == rhs;
}

DecryptionShare decrypt_share(const TpkePrivateKeyShare& private_share,
    const Ciphertext& ciphertext)
{
    // 可以在内部增加验证，或者假设调用者已验证
    // if (!verify_ciphertext(ciphertext)) { ... }

    DecryptionShare share_ui = ciphertext.u_component;
    share_ui.mult(private_share.secret);
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

namespace Hybrid {

    HybridCiphertext encrypt(AesContext& ctx, const TpkeVerificationParameters& public_params,
        BytesSpan plaintext)
    {
        std::array<Byte, 32> session_key;
        RAND_bytes(
            u8ptr(session_key.data()), session_key.size());

        Ciphertext key_ciphertext = encrypt_key(public_params, session_key);

        std::vector<Byte> pt_bytes(plaintext.begin(), plaintext.end());
        std::vector<Byte> data_ciphertext = *Utils::aes_encrypt(ctx,{ session_key.begin(), session_key.end() }, pt_bytes);

        return { .key_ciphertext = key_ciphertext, .data_ciphertext = data_ciphertext };
    }
    [[nodiscard]]
    auto decrypt(AesContext& ctx, const TpkeVerificationParameters& public_params,
        const HybridCiphertext& ciphertext,
        std::span<const PartialDecryption> shares)
        -> std::expected<std::vector<Byte>, std::error_code>
    {
        if (shares.size() < static_cast<size_t>(public_params.threshold)) {
            // Use a more specific error code if you have one
            return std::unexpected(std::make_error_code(std::errc::message_size));
        }

        auto interpolation_result = Crypto::Math::interpolate_at_zero(shares);
        if (!interpolation_result) {
            // Propagate the error from the math function (e.g., duplicate IDs)
            return std::unexpected(interpolation_result.error());
        }
        // 我们得到了恢复出的 G1 点: r * P_pub
        const P1& recovered_point = *interpolation_result;

        // 3. 从恢复的点计算出对称密钥的掩码 (mask)
        Hash256 mask = Utils::hashG(recovered_point);

        // 4. 使用掩码恢复出会话密钥
        std::vector<Byte> session_key = Utils::xor_bytes(
            ciphertext.key_ciphertext.v_component,
            mask);

        // 5. 使用恢复的会话密钥解密最终的数据
        try {
            return Utils::aes_decrypt(ctx,session_key, ciphertext.data_ciphertext);
        } catch (const std::runtime_error& e) {
            // If AES decrypt fails (e.g., bad padding), return an error.
            return std::unexpected(std::make_error_code(std::errc::illegal_byte_sequence));
        }
    }
}
}
