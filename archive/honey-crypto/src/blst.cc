#include "crypto/blst/P1.hpp" 
#include "crypto/blst/P2.hpp" 
#include <blst.h> 
#include <span> 
#include <stdint.h>

namespace Honey::Crypto::bls {
P1_Affine P1_Affine::from_P1(const P1& jac)
{
    blst_p1_affine a;
    blst_p1_to_affine(&a, &(jac.point));
    return P1_Affine(a);
}
 P2_Affine P2_Affine::from_P2(const P2& jac)
{
    blst_p2_affine a;
    blst_p2_to_affine(&a, &(jac.point));
    return P2_Affine(a);
}

 BLST_ERROR P1_Affine::core_verify(
    const P2_Affine& pk,
    bool hash_or_encode,
    std::span<const uint8_t> msg,
    std::span<const uint8_t> dst,
    std::span<const uint8_t> aug) const
{
    return blst_core_verify_pk_in_g2(pk, &point, hash_or_encode,
        msg.data(), msg.size(),
        dst.data(), dst.size(),
        aug.data(), aug.size());
}

 BLST_ERROR P2_Affine::core_verify(
    const P1_Affine& pk,
    bool hash_or_encode,
    std::span<const uint8_t> msg,
    std::span<const uint8_t> dst,
    std::span<const uint8_t> aug) const
{
    return blst_core_verify_pk_in_g1(pk, &point, hash_or_encode,
        msg.data(), msg.size(),
        dst.data(), dst.size(),
        aug.data(), aug.size());
}

} // namespace blst
