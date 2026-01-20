extern "C" {
#include <blst.h>
}

#include "crypto/blst/P1.hpp"
#include "crypto/common.hpp"
#include "crypto/error.hpp"
#include "impl_common.hpp"
#include <system_error>

namespace Honey::Crypto::bls {
class P2_Affine;
} // namespace Honey::Crypto::bls

namespace Honey::Crypto::bls {
using impl::to_native;

static_assert(sizeof(P1_Affine) == sizeof(blst_p1_affine), "P1_Affine size mismatch");
static_assert(alignof(P1_Affine) >= alignof(blst_p1_affine), "P1_Affine alignment mismatch");

P1_Affine P1_Affine::generator()
{
    P1_Affine ret {};
    *to_native<blst_p1_affine>(&ret) = *blst_p1_affine_generator();
    return ret;
}

P1_Affine P1_Affine::from_P1(const P1& jac)
{
    P1_Affine ret {};
    blst_p1_to_affine(
        to_native<blst_p1_affine>(&ret),
        to_native<blst_p1>(&jac));
    return ret;
}

std::error_code P1_Affine::core_verify(
    const P2_Affine& pk,
    bool hash_or_encode,
    BytesSpan msg,
    BytesSpan dst,
    BytesSpan aug) const
{
    BLST_ERROR err = blst_core_verify_pk_in_g2(
        to_native<blst_p2_affine>(&pk),
        to_native<blst_p1_affine>(this), // signature is in G1
        hash_or_encode,
        u8ptr(msg.data()), msg.size(),
        u8ptr(dst.data()), dst.size(),
        u8ptr(aug.data()), aug.size());

    if (err != BLST_SUCCESS)
        return Error::BlstError;
    return {};
}

} // namespace Honey::Crypto::bls
