extern "C" {
#include <blst.h>
}

#include "crypto/blst/P1.hpp"
#include "crypto/blst/Scalar.hpp"
#include "crypto/common.hpp"
#include "impl_common.hpp"
#include <array>
#include <cstring>

namespace Honey::Crypto::bls {
using impl::to_native;

static_assert(sizeof(P1) == sizeof(blst_p1), "P1 size mismatch");
static_assert(alignof(P1) >= alignof(blst_p1), "P1 alignment mismatch");

P1 P1::generator()
{
    P1 ret {};
    *to_native<blst_p1>(&ret) = *blst_p1_generator();
    return ret;
}

P1 P1::identity()
{
    P1 ret {};
    // blst 中全 0 代表无穷远点 (除了 Z 坐标需要注意，但 memset 0 通常是安全的初始状态)
    // 更正规的做法是设为无穷远
    // blst_p1 内部通常 Z=0 代表无穷远
    std::memset(to_native<blst_p1>(&ret), 0, sizeof(blst_p1));
    return ret;
}

P1 P1::from_affine(const P1_Affine& a)
{
    P1 ret {};
    blst_p1_from_affine(
        to_native<blst_p1>(&ret),
        to_native<blst_p1_affine>(&a));
    return ret;
}

P1& P1::add(const P1& a)
{
    blst_p1_add_or_double(
        to_native<blst_p1>(this),
        to_native<blst_p1>(this),
        to_native<blst_p1>(&a));
    return *this;
}

P1& P1::add(const P1_Affine& a)
{
    blst_p1_add_or_double_affine(
        to_native<blst_p1>(this),
        to_native<blst_p1>(this),
        to_native<blst_p1_affine>(&a));
    return *this;
}

P1& P1::mult(const Scalar& s)
{
    // blst_p1_mult 接收字节数组作为标量。
    // 我们的 Scalar 是 std::array<uint64, 4>。
    // 在小端序机器上，直接传指针是有效的。
    // 如果你启用了 Scalar::from_uint64 的大端序保护，这里的内存布局就是安全的。

    // 注意：blst_p1_mult 的第三个参数是 `const byte *scalar`，第四个是 bits
    blst_p1_mult(
        to_native<blst_p1>(this),
        to_native<blst_p1>(this),
        u8ptr(s.limbs.data()),
        Scalar::BIT_LENGTH);
    return *this;
}

P1& P1::neg()
{
    blst_p1_cneg(to_native<blst_p1>(this), true);
    return *this;
}

P1 P1::operator-() const
{
    P1 ret = *this;
    ret.neg();
    return ret;
}

bool operator==(const P1& a, const P1& b)
{
    return blst_p1_is_equal(
        to_native<blst_p1>(&a),
        to_native<blst_p1>(&b));
}

P1& P1::sign_with(const Scalar& s)
{
    blst_sign_pk_in_g2(
        to_native<blst_p1>(this),
        to_native<blst_p1>(this),
        to_native<blst_scalar>(&s));
    return *this;
}

P1& P1::hash_to(BytesSpan msg, BytesSpan dst, BytesSpan aug)
{
    blst_hash_to_g1(
        to_native<blst_p1>(this),
        u8ptr(msg.data()), msg.size(),
        u8ptr(dst.data()), dst.size(),
        u8ptr(aug.data()), aug.size());
    return *this;
}

P1 P1::from_hash(BytesSpan msg, BytesSpan dst)
{
    P1 ret {};
    blst_hash_to_g1(
        to_native<blst_p1>(&ret),
        u8ptr(msg.data()), msg.size(),
        u8ptr(dst.data()), dst.size(),
        nullptr, 0 // No aug
    );
    return ret;
}
[[nodiscard]]  std::array<Byte, P1::SERIALIZED_SIZE> P1::serialize() const
{
    std::array<Byte, P1::SERIALIZED_SIZE> buf {};

    blst_p1_serialize(
        u8ptr(buf.data()),
        to_native<blst_p1>(this));
    return buf;
}

[[nodiscard]] std::array<Byte, P1::COMPRESSED_SIZE> P1::compress() const
{
    std::array<Byte, P1::COMPRESSED_SIZE> buf {};
    blst_p1_compress(
        u8ptr(buf.data()),
        to_native<blst_p1>(this));
    return buf;
};

} // namespace Honey::Crypto::bls