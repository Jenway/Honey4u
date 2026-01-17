#include "crypto/blst/P1.hpp"
#include "crypto/blst/P2.hpp"
#include "impl_common.hpp"

extern "C" {
#include <blst.h>
}

namespace Honey::Crypto::bls {
using impl::to_native;

static_assert(sizeof(P1_Affine) == sizeof(blst_p1_affine), "P1_Affine size mismatch");
static_assert(alignof(P1_Affine) >= alignof(blst_p1_affine), "P1_Affine alignment mismatch");

std::expected<P1_Affine, std::error_code> P1_Affine::from_bytes(BytesSpan in)
{
    P1_Affine ret {};
    // to_native<blst_p1_affine>t_p1_deserialize 要求输入长度，通常压缩是48，非压缩是96
    // 如果 in.size() 不对，to_native<blst_p1_affine>t 会返回错误
    auto err = blst_p1_deserialize(
        to_native<blst_p1_affine>(&ret),
        u8ptr(in.data()));
    if (err != BLST_SUCCESS) {
        // 将 to_native<blst_p1_affine>T 错误转换为 std::error_code (这里简化处理，建议自定义 error_category)
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }
    return ret;
}

P1_Affine P1_Affine::generator()
{
    P1_Affine ret{};
    *to_native<blst_p1_affine>(&ret) = *blst_p1_affine_generator();
    return ret;
}

bool operator==(const P1_Affine& a, const P1_Affine& b)
{
    return blst_p1_affine_is_equal(
        to_native<blst_p1_affine>(&a),
        to_native<blst_p1_affine>(&b));
}

P1_Affine P1_Affine::from_P1(const P1& jac)
{
    P1_Affine ret{};
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
        return std::make_error_code(std::errc::protocol_error);
    return {};
}

void P1_Affine::serialize(std::span<uint8_t, 96> out) const
{
    blst_p1_affine_serialize(out.data(), to_native<blst_p1_affine>(this));
}

void P1_Affine::compress(std::span<uint8_t, 48> out) const
{
    blst_p1_affine_compress(out.data(), to_native<blst_p1_affine>(this));
}

} // namespace Honey::Crypto::bls