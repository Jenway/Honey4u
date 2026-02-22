extern "C" {
#include <blst.h>
}

#include "crypto/error.hpp"
#include "impl_common.hpp"
#include "ops.hpp"
#include "utils.hpp"

namespace Honey::Crypto::bls::ops {

using impl::to_native;

std::error_code core_verify_pk_in_g2(const P1& sig, const P2& pk,
    bool hash_or_encode, BytesSpan msg,
    BytesSpan dst, BytesSpan aug)
{
    blst_p1_affine sig_affine;
    blst_p2_affine pk_affine;
    blst_p1_to_affine(&sig_affine, to_native<blst_p1>(&sig));
    blst_p2_to_affine(&pk_affine, to_native<blst_p2>(&pk));

    BLST_ERROR err = blst_core_verify_pk_in_g2(
        &pk_affine, &sig_affine, hash_or_encode, u8ptr(msg.data()), msg.size(),
        u8ptr(dst.data()), dst.size(), u8ptr(aug.data()), aug.size());

    if (err != BLST_SUCCESS)
        return Error::BlstError;
    return {};
}
/**
 * @brief 验证双线性配对等式: e(q1, p1) == e(q2, p2)
 *
 * @param q1 G2 元素
 * @param p1 G1 元素
 * @param q2 G2 元素
 * @param p2 G1 元素
 * @return true 如果等式成立
 */
[[nodiscard]]
bool verify_pairing_equality(const P2& q1, const P1& p1, const P2& q2,
    const P1& p2)
{
    blst_p1_affine p1_aff;
    blst_p1_affine p2_aff;
    blst_p2_affine q1_aff;
    blst_p2_affine q2_aff;

    // 2. 转换坐标 (Jacobian -> Affine)
    blst_p1_to_affine(&p1_aff, impl::to_native<blst_p1>(&p1));
    blst_p2_to_affine(&q1_aff, impl::to_native<blst_p2>(&q1));
    blst_p2_to_affine(&q2_aff, impl::to_native<blst_p2>(&q2));

    // 3. 构造 e(q1, p1) == e(q2, p2)  =>  e(q1, p1) * e(q2, -p2) == 1
    //    对 p2 进行取反 (Negate G1 is cheaper)
    blst_p1 neg_p2 = *impl::to_native<blst_p1>(&p2);
    blst_p1_cneg(&neg_p2, true);
    blst_p1_to_affine(&p2_aff, &neg_p2);

    // 4. Miller Loop (累加)
    blst_fp12 loop_acc;
    blst_miller_loop(&loop_acc, &q1_aff, &p1_aff);

    blst_fp12 loop_tmp;
    blst_miller_loop(&loop_tmp, &q2_aff, &p2_aff);

    blst_fp12_mul(&loop_acc, &loop_acc, &loop_tmp);

    // 5. Final Exponentiation (最耗时的一步，只需做一次)
    blst_fp12 result;
    blst_final_exp(&result, &loop_acc);

    // 6. 检查结果是否为 1 (GT Identity)
    return blst_fp12_is_one(&result);
}

// --- P1 Operations ---

void add(P1& acc, const P1& rhs)
{
    blst_p1_add_or_double(to_native<blst_p1>(&acc), to_native<blst_p1>(&acc),
        to_native<blst_p1>(&rhs));
}

void mult(P1& p, const Scalar& s)
{
    blst_p1_mult(to_native<blst_p1>(&p), to_native<blst_p1>(&p),
        u8ptr(s.limbs.data()), // Scalar is byte array now
        Scalar::BIT_LENGTH);
}

void neg(P1& p) { blst_p1_cneg(to_native<blst_p1>(&p), true); }

void sign_with(P1& p, const Scalar& s)
{
    blst_sign_pk_in_g2(to_native<blst_p1>(&p), to_native<blst_p1>(&p),
        to_native<blst_scalar>(&s));
}

// --- P2 Operations ---

void add(P2& acc, const P2& rhs)
{
    blst_p2_add_or_double(to_native<blst_p2>(&acc), to_native<blst_p2>(&acc),
        to_native<blst_p2>(&rhs));
}

void mult(P2& p, const Scalar& s)
{
    blst_p2_mult(to_native<blst_p2>(&p), to_native<blst_p2>(&p),
        u8ptr(s.limbs.data()), Scalar::BIT_LENGTH);
}

void neg(P2& p) { blst_p2_cneg(to_native<blst_p2>(&p), true); }

void sign_with(P2& p, const Scalar& s)
{
    blst_sign_pk_in_g1(to_native<blst_p2>(&p), to_native<blst_p2>(&p),
        to_native<blst_scalar>(&s));
}

// --- Scalar Operations ---

void add(Scalar& acc, const Scalar& rhs)
{
    blst_sk_add_n_check(to_native<blst_scalar>(&acc),
        to_native<blst_scalar>(&acc),
        to_native<blst_scalar>(&rhs));
}

void sub(Scalar& acc, const Scalar& rhs)
{
    blst_sk_sub_n_check(to_native<blst_scalar>(&acc),
        to_native<blst_scalar>(&acc),
        to_native<blst_scalar>(&rhs));
}

void mult(Scalar& acc, const Scalar& rhs)
{
    blst_sk_mul_n_check(to_native<blst_scalar>(&acc),
        to_native<blst_scalar>(&acc),
        to_native<blst_scalar>(&rhs));
}

Scalar neg(const Scalar& val)
{
    Scalar ret {};
    blst_scalar zero = { 0 };
    blst_sk_sub_n_check(to_native<blst_scalar>(&ret), &zero,
        to_native<blst_scalar>(&val));
    return ret;
}

Scalar inverse(const Scalar& val)
{
    Scalar ret {};
    blst_sk_inverse(to_native<blst_scalar>(&ret), to_native<blst_scalar>(&val));
    return ret;
}

} // namespace Honey::Crypto::bls::ops
