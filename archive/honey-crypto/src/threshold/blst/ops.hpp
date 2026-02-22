#pragma once

#include "crypto/threshold/blst/P1.hpp"
#include "crypto/threshold/blst/P2.hpp"
#include "crypto/threshold/blst/Scalar.hpp"
#include "crypto/types.hpp"
#include "impl_common.hpp"
#include <system_error>

namespace Honey::Crypto::bls {
namespace ops {

    void add(P1& acc, const P1& rhs);
    void mult(P1& p, const Scalar& s);
    void neg(P1& p);
    void sign_with(P1& p, const Scalar& s);

    void add(P2& acc, const P2& rhs);
    void mult(P2& p, const Scalar& s);
    void neg(P2& p);
    void sign_with(P2& p, const Scalar& s);

    void add(Scalar& acc, const Scalar& rhs);
    void sub(Scalar& acc, const Scalar& rhs);
    void mult(Scalar& acc, const Scalar& rhs);
    Scalar neg(const Scalar& val);
    Scalar inverse(const Scalar& val);
    using impl::to_native;

    /**
     * @brief 验证签名 pk 对消息 msg 的有效性
     */
    std::error_code core_verify_pk_in_g2(const P1& sig, const P2& pk,
        bool hash_or_encode, BytesSpan msg,
        BytesSpan dst, BytesSpan aug);
    /**
     * @brief 验证双线性配对等式: e(q1, p1) == e(q2, p2)
     */
    [[nodiscard]]
    bool verify_pairing_equality(const P2& q1, const P1& p1, const P2& q2,
        const P1& p2);

} // namespace ops

inline Scalar operator-(const Scalar& s) { return ops::neg(s); }

inline Scalar operator-(const Scalar& lhs, const Scalar& rhs)
{
    Scalar res = lhs;
    ops::sub(res, rhs);
    return res;
}

inline Scalar operator*=(Scalar& lhs, const Scalar& rhs)
{
    ops::mult(lhs, rhs);
    return lhs;
}

inline bool operator==(const P1& lhs, const P1& rhs) { return lhs.equals(rhs); }

inline bool operator==(const P2& lhs, const P2& rhs) { return lhs.equals(rhs); }

} // namespace Honey::Crypto::bls
