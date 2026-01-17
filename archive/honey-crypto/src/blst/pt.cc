extern "C" {
#include <blst.h>
}

#include "crypto/blst/P1.hpp"
#include "crypto/blst/P2.hpp"
#include "crypto/blst/PT.hpp"
#include "impl_common.hpp"

namespace Honey::Crypto::bls {
static_assert(sizeof(PT) == sizeof(blst_fp12), "PT size mismatch");
static_assert(alignof(PT) >= alignof(blst_fp12), "PT alignment mismatch");

using impl::to_native;

PT::PT(const P1_Affine& p)
{
    blst_aggregated_in_g1(
        to_native<blst_fp12>(this),
        to_native<blst_p1_affine>(&p));
}

PT::PT(const P2_Affine& q)
{
    blst_aggregated_in_g2(
        to_native<blst_fp12>(this),
        to_native<blst_p2_affine>(&q));
}

PT::PT(const P2_Affine& q, const P1_Affine& p)
{
    blst_miller_loop(
        to_native<blst_fp12>(this), 
        to_native<blst_p2_affine>(&q), 
        to_native<blst_p1_affine>(&p));
}

PT::PT(const P2& q, const P1& p)
{
    P2_Affine q_aff = P2_Affine::from_P2(q);
    P1_Affine p_aff = P1_Affine::from_P1(p);

    blst_miller_loop(
        to_native<blst_fp12>(this), 
        to_native<blst_p2_affine>(&q_aff), 
        to_native<blst_p1_affine>(&p_aff));
}

PT::PT(const P1_Affine& p, const P2_Affine& q)
    : PT(q, p)
{
}
PT::PT(const P1& p, const P2& q)
    : PT(q, p)
{
}

PT& PT::final_exp()
{
    blst_final_exp(to_native<blst_fp12>(this), to_native<blst_fp12>(this));
    return *this;
}

} // namespace Honey::Crypto::bls