#include "crypto/threshold/pke.hpp"
#include "blst/ops.hpp"
#include "crypto/error.hpp"
#include "crypto/threshold/blst/Scalar.hpp"
#include "threshold/interpolate.hpp"
#include "threshold/key_gen.hpp"
#include "utils.hpp"
#include <array>
#include <cstring>
#include <expected>
#include <openssl/rand.h>
#include <span>
#include <system_error>
#include <vector>

namespace Honey::Crypto::Threshold::Pke {

namespace {
    std::array<Byte, 32> xor_bytes(std::span<const Byte, 32> a, std::span<const Byte, 32> b)
    {
        std::array<Byte, 32> res;
        for (size_t i = 0; i < a.size(); ++i) {
            res[i] = a[i] ^ b[i];
        }
        return res;
    }
    /// 验证密钥封装的一致性
    ///
    /// e(w, G1) == e(H(u,v), u)
    bool verify_encapsulation(const Ciphertext& ciphertext)
    {
        // 映射参数: (q1, p1, q2, p2) -> (G2, G1, G2, G1)
        return bls::ops::verify_pairing_equality(
            ciphertext.w, // q1: w
            G1Point::generator(), // p1: G1_gen
            Utils::hashH(ciphertext.u, ciphertext.v), // q2: H(u,v)
            ciphertext.u // p2: u
        );
    }
} // namespace

/// 验证解密份额
///  e(G2, ui) == e(yi, u)
bool verify_share(const PublicParameters& public_params,
    const PartialDecryptionShare& decryption,
    const Ciphertext& ciphertext)
{
    auto id = decryption.player_id;
    if (id < 1 || id > public_params.total_players)
        return false;

    return bls::ops::verify_pairing_equality(
        G2Point::generator(), // q1: G2_gen
        decryption.value, // p1: ui (份额)
        public_params.verification_vector[id - 1], // q2: yi (公钥份额)
        ciphertext.u // p2: u (密钥封装中的u)
    );
}

auto generate_keys(uint32_t num_players, uint32_t threshold)
    -> std::expected<KeySet, std::error_code>
{
    return Threshold::generate_keys<MasterPublicKey, VerificationKey>(num_players, threshold);
}

Ciphertext seal(
    const MasterPublicKey& master_public_key,
    PlainText msg)
{
    auto random_scalar = *Scalar::random();

    G1Point u = G1Point::generator();
    bls::ops::mult(u, random_scalar);

    G1Point mask_point = master_public_key;
    bls::ops::mult(mask_point, random_scalar);
    auto mask = Utils::hashG(mask_point);

    auto v = xor_bytes(msg, mask);

    G2Point h = Utils::hashH(u, v);
    G2Point w = h;
    bls::ops::mult(w, random_scalar);

    Ciphertext result { .u = u, .v = v, .w = w };
    return result;
}

auto partial_open(
    const PrivateKeyShare& private_key_share,
    const Ciphertext& ciphertext) -> std::expected<PartialDecryptionShare, std::error_code>
{
    if (!verify_encapsulation(ciphertext)) {
        return std::unexpected(make_error_code(Crypto::Error::InvalidCiphertext));
    }
    // 生成解密份额
    auto share_value = ciphertext.u;
    bls::ops::mult(share_value, private_key_share.secret);

    return PartialDecryptionShare {
        .player_id = static_cast<PlayerIndex>(private_key_share.player_id),
        .value = share_value
    };
}

[[nodiscard]]
auto open(const PublicParameters& public_params,
    const Ciphertext& ciphertext,
    std::span<const PartialDecryptionShare> shares)
    -> std::expected<std::array<Byte, 32>, std::error_code>
{
    if (shares.size() < static_cast<size_t>(public_params.threshold)) {
        return std::unexpected(std::make_error_code(std::errc::message_size));
    }
    for (const auto& share : shares) {
        if (!verify_share(public_params, share, ciphertext)) {
            return std::unexpected(make_error_code(std::errc::bad_message));
        }
    }

    auto interpolation_result = Crypto::Math::interpolate_at_zero(shares);
    if (!interpolation_result) {
        return std::unexpected(interpolation_result.error());
    }
    const auto& recovered_point = *interpolation_result;

    // 恢复会话密钥: K = v ⊕ H_G(recovered_point)
    auto mask = Utils::hashG(recovered_point);

    std::array<Byte, 32> session_key;
    for (size_t i = 0; i < 32; ++i) {
        session_key[i] = ciphertext.v[i] ^ mask[i];
    }

    return session_key;
}

} // namespace Honey::Crypto::Threshold::Pke

/*                     \
 ===================== \
 Unit Test             \
 ==================    \
*/                     \
#ifndef DOCTEST_CONFIG_DISABLE
#include <array>
#include <doctest/doctest.h>
#include <string>
#include <vector>

namespace Honey::Crypto::Threshold::Pke {

namespace {

    std::array<Byte, 32> string_to_block32(const std::string& s)
    {
        std::array<Byte, 32> out {};
        std::memcpy(out.data(), s.data(), std::min<size_t>(32, s.size()));
        return out;
    }

} // namespace

struct TpkeTest {
    static constexpr uint32_t N = 5;
    static constexpr uint32_t K = 3;

    KeySet key_set;

    TpkeTest()
    {
        auto ks = generate_keys(N, K);
        REQUIRE(ks.has_value());
        key_set = *ks;
    }
};

TEST_CASE_FIXTURE(TpkeTest, "TPKE.seal_and_open_success")
{
    auto msg = string_to_block32("HoneyBadger BFT is robust!");

    Ciphertext ct = seal(key_set.public_params.master_public_key, msg);

    std::vector<PartialDecryptionShare> shares;
    for (int id : { 1, 3, 5 }) {
        auto s = partial_open(key_set.private_shares[id - 1], ct);
        REQUIRE(s.has_value());
        shares.push_back(*s);
    }

    auto opened = open(key_set.public_params, ct, shares);
    REQUIRE(opened.has_value());
    CHECK(*opened == msg);
}

TEST_CASE_FIXTURE(TpkeTest, "TPKE.open_fails_with_invalid_share")
{
    auto msg = string_to_block32("This should not decrypt");
    Ciphertext ct = seal(key_set.public_params.master_public_key, msg);

    std::vector<PartialDecryptionShare> shares;

    auto s1 = partial_open(key_set.private_shares[0], ct);
    auto s2 = partial_open(key_set.private_shares[1], ct);
    REQUIRE(s1.has_value());
    REQUIRE(s2.has_value());

    shares.push_back(*s1);
    shares.push_back(*s2);

    // 构造一个伪造份额
    PartialDecryptionShare bad {
        .player_id = 3,
        .value = G1Point::generator()
    };
    shares.push_back(bad);

    auto opened = open(key_set.public_params, ct, shares);
    CHECK_FALSE(opened.has_value());
}

TEST_CASE_FIXTURE(TpkeTest, "TPKE.open_fails_with_insufficient_shares")
{
    auto msg = string_to_block32("Not enough shares");
    Ciphertext ct = seal(key_set.public_params.master_public_key, msg);

    std::vector<PartialDecryptionShare> shares;
    auto s1 = partial_open(key_set.private_shares[0], ct);
    auto s2 = partial_open(key_set.private_shares[1], ct);
    REQUIRE(s1.has_value());
    REQUIRE(s2.has_value());

    shares.push_back(*s1);
    shares.push_back(*s2);

    auto opened = open(key_set.public_params, ct, shares);
    CHECK_FALSE(opened.has_value());
}

TEST_CASE_FIXTURE(TpkeTest, "TPKE.open_fails_with_duplicate_player_id")
{
    auto msg = string_to_block32("Duplicate share");
    Ciphertext ct = seal(key_set.public_params.master_public_key, msg);

    auto s = partial_open(key_set.private_shares[0], ct);
    REQUIRE(s.has_value());

    std::vector<PartialDecryptionShare> shares {
        *s,
        *s, // duplicate
        *s
    };

    auto opened = open(key_set.public_params, ct, shares);
    CHECK_FALSE(opened.has_value());
}
} // namespace Honey::Crypto::Threshold::Pke
#endif // DOCTEST_CONFIG_DISABLE
