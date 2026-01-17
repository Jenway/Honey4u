extern "C" {
#include <blst.h>
}
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

void P2_Affine::serialize(std::span<uint8_t, P2::SERIALIZED_SIZE> out) const
{
    blst_p2_affine_serialize(out.data(), to_native<blst_p2_affine>(this));
}

void P2_Affine::compress(std::span<uint8_t, P2::COMPRESSED_SIZE> out) const
{
    blst_p2_affine_compress(out.data(), to_native<blst_p2_affine>(this));
}

} // namespace Honey::Crypto::bls