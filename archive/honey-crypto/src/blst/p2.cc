extern "C" {
#include <blst.h>
}

#include "crypto/blst/P2.hpp"
#include "crypto/blst/Scalar.hpp"
#include "crypto/common.hpp"
#include "impl_common.hpp"
#include <array>
#include <cstdint>
#include <cstring>
#include <span>

namespace Honey::Crypto::bls {

static_assert(sizeof(P2) == sizeof(blst_p2), "P2 size mismatch");
static_assert(alignof(P2) >= alignof(blst_p2), "P2 alignment mismatch");

using impl::to_native;

P2 P2::generator()
{
    P2 ret {};
    *to_native<blst_p2>(&ret) = *blst_p2_generator();
    return ret;
}

P2 P2::identity()
{
    P2 ret {};
    std::memset(to_native<blst_p2>(&ret), 0, sizeof(blst_p2));
    return ret;
}

P2 P2::from_affine(const P2_Affine& a)
{
    P2 ret {};
    blst_p2_from_affine(
        to_native<blst_p2>(&ret),
        to_native<blst_p2_affine>(&a));
    return ret;
}

bool operator==(const P2& a, const P2& b)
{
    return blst_p2_is_equal(to_native<blst_p2>(&a), to_native<blst_p2>(&b));
}

void P2::serialize(std::span<uint8_t, P2::SERIALIZED_SIZE> out) const
{
    blst_p2_serialize(out.data(), to_native<blst_p2>(this));
}

void P2::compress(std::span<uint8_t, P2::COMPRESSED_SIZE> out) const
{
    blst_p2_compress(out.data(), to_native<blst_p2>(this));
}

P2& P2::add(const P2& a)
{
    blst_p2_add_or_double(to_native<blst_p2>(this), to_native<blst_p2>(this), to_native<blst_p2>(&a));
    return *this;
}

P2& P2::add(const P2_Affine& a)
{
    blst_p2_add_or_double_affine(to_native<blst_p2>(this), to_native<blst_p2>(this), to_native<blst_p2_affine>(&a));
    return *this;
}


P2& P2::mult(const Scalar& s)
{
    // s.limbs 本质上就是 256bit 的数据，转为 byte 指针传递给 mult
    blst_p2_mult(
        to_native<blst_p2>(this),
        to_native<blst_p2>(this),
        u8ptr(s.limbs.data()),
        Scalar::BIT_LENGTH);
    return *this;
}

P2& P2::neg()
{
    blst_p2_cneg(to_native<blst_p2>(this), true);
    return *this;
}

P2 P2::operator-() const
{
    P2 ret = *this;
    ret.neg();
    return ret;
}

P2& P2::sign_with(const Scalar& s)
{
    // blst_sign_pk_in_g1 生成 G2 上的签名 (PK 在 G1)
    blst_sign_pk_in_g1(to_native<blst_p2>(this), to_native<blst_p2>(this), to_native<blst_scalar>(&s));
    return *this;
}

P2& P2::hash_to(BytesSpan msg, BytesSpan dst, BytesSpan aug)
{
    blst_hash_to_g2(
        to_native<blst_p2>(this),
        u8ptr(msg.data()), msg.size(),
        u8ptr(dst.data()), dst.size(),
        u8ptr(aug.data()), aug.size());
    return *this;
}

P2 P2::from_hash(BytesSpan msg, BytesSpan dst)
{
    P2 ret {};
    blst_hash_to_g2(
        to_native<blst_p2>(&ret),
        u8ptr(msg.data()), msg.size(),
        u8ptr(dst.data()), dst.size(),
        nullptr, 0);
    return ret;
}

} // namespace Honey::Crypto::bls