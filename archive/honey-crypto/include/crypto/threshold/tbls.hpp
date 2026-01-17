#include "crypto/blst/P1.hpp"
#include "crypto/blst/P2.hpp"
#include "crypto/common.hpp"
#include "crypto/threshold/key_gen.hpp"
#include <expected>
#include <span>
#include <system_error>

namespace Honey::Crypto::Tbls {

using bls::P1;
using bls::P2;

using bls::Scalar;

using MasterPublicKey = P2; // 主公钥（G2点）
using VerificationKey = P2; // 验证公钥（G2点）

using TblsVerificationParameters = Threshold::VerificationParameters<MasterPublicKey, VerificationKey>;
using TblsPrivateKeyShare = Threshold::PrivateKeyShare;
using TblsKeySet = Threshold::DistributedKeySet<MasterPublicKey, VerificationKey>;

using Signature = P1; // 完整签名（G1点）
using SignatureShare = P1; // 签名份额（G1点）
struct PartialSignature {
    int player_id;
    SignatureShare value;
};

inline auto generate_keys(int players, int k)
    -> std::expected<TblsKeySet, std::error_code>
{
    return Threshold::generate_keys<MasterPublicKey, VerificationKey>(players, k);
}

[[nodiscard]]
PartialSignature sign_share(const TblsPrivateKeyShare& share, BytesSpan message);

[[nodiscard]]
auto verify_share(const TblsVerificationParameters& params,
    const SignatureShare& partial_sig,
    BytesSpan message,
    int player_id)
    -> std::expected<void, std::error_code>;

[[nodiscard]]
auto combine_partial_signatures(const TblsVerificationParameters& public_params,
    std::span<const PartialSignature> partial_signatures)
    -> std::expected<Signature, std::error_code>;

[[nodiscard]]
auto verify_signature(const TblsVerificationParameters& public_params,
    BytesSpan message,
    const Signature& signature)
    -> std::expected<void, std::error_code>;

}  // namespace Honey::Crypto::Tbls
