#include "ops.hpp"
#include "impl_common.hpp"
#include "impl_utils.hpp"
#include <cstring>

namespace Honey::Crypto::bls::ops {

using impl::to_native;

// --- P1 Operations ---

void add(P1& acc, const P1& rhs)
{
    blst_p1_add_or_double(
        to_native<blst_p1>(&acc),
        to_native<blst_p1>(&acc),
        to_native<blst_p1>(&rhs));
}

void mult(P1& p, const Scalar& s)
{
    blst_p1_mult(
        to_native<blst_p1>(&p),
        to_native<blst_p1>(&p),
        u8ptr(s.limbs.data()), // Scalar is byte array now
        Scalar::BIT_LENGTH);
}

void neg(P1& p)
{
    blst_p1_cneg(to_native<blst_p1>(&p), true);
}

void sign_with(P1& p, const Scalar& s)
{
    blst_sign_pk_in_g2(
        to_native<blst_p1>(&p),
        to_native<blst_p1>(&p),
        to_native<blst_scalar>(&s));
}

void hash_to(P1& p, BytesSpan msg, BytesSpan dst, BytesSpan aug)
{
    blst_hash_to_g1(
        to_native<blst_p1>(&p),
        u8ptr(msg.data()), msg.size(),
        u8ptr(dst.data()), dst.size(),
        u8ptr(aug.data()), aug.size());
}

bool is_equal(const P1& a, const P1& b)
{
    return blst_p1_is_equal(
        to_native<blst_p1>(&a),
        to_native<blst_p1>(&b));
}

// --- P2 Operations ---

void add(P2& acc, const P2& rhs)
{
    blst_p2_add_or_double(
        to_native<blst_p2>(&acc),
        to_native<blst_p2>(&acc),
        to_native<blst_p2>(&rhs));
}

void mult(P2& p, const Scalar& s)
{
    blst_p2_mult(
        to_native<blst_p2>(&p),
        to_native<blst_p2>(&p),
        u8ptr(s.limbs.data()),
        Scalar::BIT_LENGTH);
}

void neg(P2& p)
{
    blst_p2_cneg(to_native<blst_p2>(&p), true);
}

void sign_with(P2& p, const Scalar& s)
{
    blst_sign_pk_in_g1(
        to_native<blst_p2>(&p),
        to_native<blst_p2>(&p),
        to_native<blst_scalar>(&s));
}

void hash_to(P2& p, BytesSpan msg, BytesSpan dst, BytesSpan aug)
{
    blst_hash_to_g2(
        to_native<blst_p2>(&p),
        u8ptr(msg.data()), msg.size(),
        u8ptr(dst.data()), dst.size(),
        u8ptr(aug.data()), aug.size());
}

bool is_equal(const P2& a, const P2& b)
{
    return blst_p2_is_equal(
        to_native<blst_p2>(&a),
        to_native<blst_p2>(&b));
}

// --- Scalar Operations ---

void add(Scalar& acc, const Scalar& rhs)
{
    blst_sk_add_n_check(
        to_native<blst_scalar>(&acc),
        to_native<blst_scalar>(&acc),
        to_native<blst_scalar>(&rhs));
}

void sub(Scalar& acc, const Scalar& rhs)
{
    blst_sk_sub_n_check(
        to_native<blst_scalar>(&acc),
        to_native<blst_scalar>(&acc),
        to_native<blst_scalar>(&rhs));
}

void mult(Scalar& acc, const Scalar& rhs)
{
    blst_sk_mul_n_check(
        to_native<blst_scalar>(&acc),
        to_native<blst_scalar>(&acc),
        to_native<blst_scalar>(&rhs));
}

Scalar neg(const Scalar& val)
{
    Scalar ret {};
    blst_scalar zero = { 0 };
    blst_sk_sub_n_check(
        to_native<blst_scalar>(&ret),
        &zero,
        to_native<blst_scalar>(&val));
    return ret;
}

Scalar inverse(const Scalar& val)
{
    Scalar ret {};
    blst_sk_inverse(
        to_native<blst_scalar>(&ret),
        to_native<blst_scalar>(&val));
    return ret;
}

} // namespace Honey::Crypto::bls::ops
