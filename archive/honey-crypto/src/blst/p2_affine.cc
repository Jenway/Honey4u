extern "C" {
#include <blst.h>
}
#include "P2_Affine.hpp"
#include "crypto/blst/P2.hpp"
#include "impl_common.hpp"
#include <cstdint>
#include <span>

namespace Honey::Crypto::bls {

static_assert(sizeof(P2_Affine) == sizeof(blst_p2_affine), "P2_Affine size mismatch");
static_assert(alignof(P2_Affine) >= alignof(blst_p2_affine), "P2_Affine alignment mismatch");

using impl::to_native;

P2_Affine P2_Affine::generator()
{
    P2_Affine ret {};
    *to_native<blst_p2_affine>(&ret) = *blst_p2_affine_generator();
    return ret;
}

P2_Affine P2_Affine::from_P2(const P2& jac)
{
    P2_Affine ret {};
    blst_p2_to_affine(to_native<blst_p2_affine>(&ret), to_native<blst_p2>(&jac));
    return ret;
}

} // namespace Honey::Crypto::bls
