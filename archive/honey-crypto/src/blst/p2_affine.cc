extern "C" {
#include <blst.h>
}
#include "crypto/blst/P1.hpp"
#include "crypto/blst/P2.hpp"
#include "impl_common.hpp"

namespace Honey::Crypto::bls {

static_assert(sizeof(P2_Affine) == sizeof(blst_p2_affine), "P2_Affine size mismatch");
static_assert(alignof(P2_Affine) >= alignof(blst_p2_affine), "P2_Affine alignment mismatch");

using impl::to_native;

std::expected<P2_Affine, std::error_code> P2_Affine::from_bytes(BytesSpan in)
{
    P2_Affine ret {};
    BLST_ERROR err = blst_p2_deserialize(to_native<blst_p2_affine>(&ret), u8ptr(in.data()));
    if (err != BLST_SUCCESS)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    return ret;
}

P2_Affine P2_Affine::generator()
{
    P2_Affine ret {};
    *to_native<blst_p2_affine>(&ret) = *blst_p2_affine_generator();
    return ret;
}

bool operator==(const P2_Affine& a, const P2_Affine& b)
{
    return blst_p2_affine_is_equal(to_native<blst_p2_affine>(&a), to_native<blst_p2_affine>(&b));
}

bool P2_Affine::on_curve() const { return blst_p2_affine_on_curve(to_native<blst_p2_affine>(this)); }
bool P2_Affine::in_group() const { return blst_p2_affine_in_g2(to_native<blst_p2_affine>(this)); }
bool P2_Affine::is_inf() const { return blst_p2_affine_is_inf(to_native<blst_p2_affine>(this)); }

std::error_code P2_Affine::core_verify(
    const P1_Affine& pk,
    bool hash_or_encode,
    BytesSpan msg,
    BytesSpan dst,
    BytesSpan aug) const
{
    // 注意：blst_core_verify_pk_in_g1 意味着 PK 在 G1，Signature (this) 在 G2
    BLST_ERROR err = blst_core_verify_pk_in_g1(
        to_native<blst_p1_affine>(&pk),
        to_native<blst_p2_affine>(this),
        hash_or_encode,
        u8ptr(msg.data()), msg.size(),
        u8ptr(dst.data()), dst.size(),
        u8ptr(aug.data()), aug.size());

    if (err != BLST_SUCCESS)
        return std::make_error_code(std::errc::protocol_error);
    return {};
}

P2_Affine P2_Affine::from_P2(const P2& jac)
{
    P2_Affine ret {};
    blst_p2_to_affine(to_native<blst_p2_affine>(&ret), to_native<blst_p2>(&jac));
    return ret;
}

void P2_Affine::serialize(std::span<uint8_t, 192> out) const
{
    blst_p2_affine_serialize(out.data(), to_native<blst_p2_affine>(this));
}

void P2_Affine::compress(std::span<uint8_t, 96> out) const
{
    blst_p2_affine_compress(out.data(), to_native<blst_p2_affine>(this));
}

} // namespace Honey::Crypto::bls