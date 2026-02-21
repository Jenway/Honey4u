#pragma once

#include "crypto/threshold/types.hpp"
#include "crypto/types.hpp"
#include "types.hpp"
#include <cstdint>
#include <expected>
#include <span>
#include <system_error>

namespace Honey::Crypto::Threshold::Sig {

using Byte = std::byte;
using PlayerIndex = uint32_t;

using MasterPublicKey = G2Point; // 主公钥（G2点）
using VerificationKey = G2Point; // 验证公钥（G2点）
using PrivateKeyShare = PrivateKeyShare;

using Signature = G1Point; // 完整签名（G1点）
using SignatureShare = G1Point; // 签名份额（G1点）

using PublicParameters = VerificationParameters<MasterPublicKey, VerificationKey>;
using KeySet = DistributedKeySet<MasterPublicKey, VerificationKey>;

struct PartialSignature {
    int player_id;
    SignatureShare value;
};

auto generate_keys(uint32_t players, uint32_t k)
    -> std::expected<KeySet, std::error_code>;

[[nodiscard]]
PartialSignature sign(const PrivateKeyShare& share, BytesSpan message);

[[nodiscard]]
auto verify_share(const PublicParameters& params,
    const PartialSignature& partial_signature,
    BytesSpan message)
    -> std::expected<void, std::error_code>;

[[nodiscard]]
auto validate(const PublicParameters& public_params,
    BytesSpan message,
    std::span<const PartialSignature> partial_signatures)
    -> std::expected<void, std::error_code>;

} // namespace Honey::Crypto::Threshold::Sig
