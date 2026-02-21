#pragma once

#include "crypto/threshold/types.hpp"

#include <cstdint>
#include <expected>
#include <span>
#include <system_error>

namespace Honey::Crypto::Threshold::Pke {

using Byte = std::byte;
using PlayerIndex = uint32_t;
using Threshold::G1Point;
using Threshold::G2Point;
using Threshold::Scalar;

// --- 密码学语义类型 ---

using MasterPublicKey = G1Point; // 主公钥 MPK
using VerificationKey = G2Point; // 份额验证密钥 V_i
using PrivateKeyShare = Threshold::PrivateKeyShare; // 私钥份额 SK_i
using DecryptionShare = G1Point; // 解密份额 U_i

// 公开参数，包含验证一个分布式密钥集所需的所有信息
using PublicParameters = VerificationParameters<MasterPublicKey, VerificationKey>;
// 完整的分布式密钥集，包含公参和所有私钥份额
using KeySet = DistributedKeySet<MasterPublicKey, VerificationKey>;

static constexpr size_t PTSize = 32;
using PlainText = std::array<Byte, PTSize>;

struct Ciphertext {
    constexpr static size_t VSize = 32;

    G1Point u; // 临时公钥 U = r * G1
    // V = K ⊕ H_G(r * MPK)，这里 H_G 输出固定为32字节
    std::array<Byte, VSize> v;
    G2Point w; // 一致性证明 W = r * H_H(U, V)
};

// 单个参与者生成的解密份额
struct PartialDecryptionShare {
    PlayerIndex player_id; // 份额所有者的索引
    DecryptionShare value; // 份额的值
};

/**
 * @brief 生成一个分布式的 TPKE 密钥集。
 * @param num_players 参与者总数。
 * @param threshold 恢复密钥所需的最小份额数。
 * @return 成功时返回完整的密钥集，失败时返回错误码。
 */
[[nodiscard]]
auto generate_keys(uint32_t num_players, uint32_t threshold)
    -> std::expected<KeySet, std::error_code>;

/**
 * @brief 使用 TPKE 生成密钥封装。
 *
 * @param master_public_key TPKE 的主公钥。
 * @param msg 要封装的信息（32字节 only support）。
 * @return 密钥封装和生成的会话密钥。
 */
[[nodiscard]]
auto seal(const MasterPublicKey& master_public_key, PlainText msg) -> Ciphertext;

/**
 * @brief 节点使用自己的私钥份额为给定的密钥封装生成一个解密份额。
 *
 * @param private_key_share 节点持有的私钥份额。
 * @param ciphertext 密钥封装部分。
 * @return 成功时返回一个有效的解密份额，失败（如密钥封装无效）则返回错误码。
 */
[[nodiscard]]
auto partial_open(
    const PrivateKeyShare& private_key_share,
    const Ciphertext& ciphertext)
    -> std::expected<PartialDecryptionShare, std::error_code>;

/**
 * @brief 验证单个解密份额的有效性。
 *
 * @param public_params 用于验证份额的公共参数。
 * @param decryption 要验证的解密份额。
 * @param ciphertext 密钥封装。
 * @return 如果份额有效则返回 true，否则返回 false。
 */
bool verify_share(const PublicParameters& public_params,
    const PartialDecryptionShare& decryption,
    const Ciphertext& ciphertext);

/**
 * @brief 聚合足够数量的解密份额来恢复会话密钥。
 *
 * @param public_params 用于验证份额的公共参数。
 * @param ciphertext 密钥封装。
 * @param shares 来自不同参与者的解密份额集合视图。
 * @return 成功时返回恢复的 32 字节会话密钥，失败（如份额不足/无效）则返回错误码。
 */
[[nodiscard]]
auto open(
    const PublicParameters& public_params,
    const Ciphertext& ciphertext,
    std::span<const PartialDecryptionShare> shares) -> std::expected<std::array<Byte, 32>, std::error_code>;

} // namespace Honey::Crypto::Tpke
