#pragma once
#include "crypto/blst/P1.hpp"
#include "crypto/blst/P2.hpp"
#include "crypto/blst/Scalar.hpp"
#include "crypto/threshold/types.hpp"
#include <expected>
#include <memory>
#include <span>
#include <system_error>
#include <vector>

namespace Honey::Crypto::Tpke {

// BLS 基础类型
using P1 = bls::P1;
using P2 = bls::P2;
using Scalar = bls::Scalar;

using MasterPublicKey = P1; // 主公钥 (G1 点)
using VerificationKey = P2; // 份额验证密钥 (G2 点)
using DecryptionShare = P1; // 解密份额 (G1 点)

using TpkeVerificationParameters = Threshold::VerificationParameters<MasterPublicKey, VerificationKey>;
using TpkePrivateKeyShare = Threshold::PrivateKeyShare;
using TpkeKeySet = Threshold::DistributedKeySet<MasterPublicKey, VerificationKey>;

struct Ciphertext {
    P1 u_component; // U
    std::vector<Byte> v_component; // V
    P2 w_component; // W

    // Serialization
    [[nodiscard]] std::vector<Byte> serialize() const;
    [[nodiscard]] static std::expected<Ciphertext, std::error_code>
    deserialize(std::span<const Byte> data);
};

struct PartialDecryption {
    int player_id;
    DecryptionShare value;
};

struct HybridCiphertext {
    Ciphertext key_ciphertext;
    std::vector<Byte> data_ciphertext;

    // Serialization
    [[nodiscard]] std::vector<Byte> serialize() const;
    [[nodiscard]] static std::expected<HybridCiphertext, std::error_code>
    deserialize(std::span<const Byte> data);
};

// Opaque context for encryption/decryption state (e.g., AES context)
class Context {
public:
    Context();
    ~Context();
    Context(Context&&) noexcept;
    Context& operator=(Context&&) noexcept;

    // Implementation details hidden via Pimpl
    struct Impl;
    Impl* impl() { return pimpl_.get(); }

private:
    std::unique_ptr<Impl> pimpl_;
};

auto generate_keys(int players, int k) -> std::expected<TpkeKeySet, std::error_code>;

[[nodiscard]]
HybridCiphertext encrypt(Context& ctx, const TpkeVerificationParameters& public_params,
    BytesSpan plaintext);

[[nodiscard]]
auto decrypt(Context& ctx, const TpkeVerificationParameters& public_params,
    const HybridCiphertext& ciphertext,
    std::span<const PartialDecryption> shares)
    -> std::expected<std::vector<Byte>, std::error_code>;

namespace detail {

    // 加密一个 32 字节的对称密钥
    [[nodiscard]]
    Ciphertext encrypt_key(const TpkeVerificationParameters& public_params,
        std::span<const Byte, 32> symmetric_key);

    // 验证密文的完整性 (e.g., ZK-proof)
    [[nodiscard]]
    bool verify_ciphertext(const Ciphertext& ciphertext);

    // 生成解密份额
    [[nodiscard]]
    DecryptionShare decrypt_share(const TpkePrivateKeyShare& private_share,
        const Ciphertext& ciphertext);

    // 验证解密份额
    [[nodiscard]]
    bool verify_share(const TpkeVerificationParameters& public_params,
        const PartialDecryption& decryption,
        const Ciphertext& ciphertext);

} // namespace detail
} // namespace Honey::Crypto::Tpke
