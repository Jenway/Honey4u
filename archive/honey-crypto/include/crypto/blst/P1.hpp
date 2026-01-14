#pragma once

#include <cassert>
#include <cstddef>
#include <cstring>
#include <span>
#include <expected>

extern "C" {
#include <blst.h>
}
#include "Scalar.hpp"

namespace Honey::Crypto::bls {

class P1;
class P2_Affine;

class P1_Affine {
private:
    ::blst_p1_affine point;

    P1_Affine() = default;

    explicit P1_Affine(const blst_p1_affine& p)
        : point(p)
    {
    }

public:
    /* ---------- factories ---------- */

    static std::expected<P1_Affine, BLST_ERROR>
    from_bytes(std::span<const uint8_t> in)
    {
        blst_p1_affine p;
        BLST_ERROR err = blst_p1_deserialize(&p, in.data());
        if (err != BLST_SUCCESS)
            return std::unexpected(err);
        return P1_Affine(p);
    }

    static P1_Affine generator()
    {
        return P1_Affine(*blst_p1_affine_generator());
    }

    P1_Affine dup() const { return *this; }


    BLST_ERROR core_verify(
        const P2_Affine& pk,
        bool hash_or_encode,
        std::span<const uint8_t> msg,
        std::span<const uint8_t> dst,
        std::span<const uint8_t> aug = {}) const;
    static P1_Affine from_P1(const P1& jac);

private:
    friend class P2_Affine;
    friend class P1;
    friend class PT;

    operator const blst_p1_affine*() const { return &point; }
};

struct P1 {
private:
    blst_p1 point;

    P1() = default;

    explicit P1(const blst_p1& p)
        : point(p)
    {
    }

public:
    /* ---------- factories ---------- */

    static P1 generator()
    {
        return P1(*blst_p1_generator());
    }

    static std::expected<P1, BLST_ERROR>
    from_bytes(std::span<const uint8_t> in)
    {
        blst_p1_affine a;
        BLST_ERROR err = blst_p1_deserialize(&a, in.data());
        if (err != BLST_SUCCESS)
            return std::unexpected(err);

        blst_p1 p;
        blst_p1_from_affine(&p, &a);
        return P1(p);
    }

    static P1 from_affine(const P1_Affine& a)
    {
        blst_p1 p;
        blst_p1_from_affine(&p, a);
        return P1(p);
    }

    /* ---------- observers ---------- */

    P1 dup() const { return *this; }


    /* ---------- mutators ---------- */

    P1& add(const P1& a)
    {
        blst_p1_add_or_double(&point, &point, a);
        return *this;
    }

    P1& add(const P1_Affine& a)
    {
        blst_p1_add_or_double_affine(&point, &point, a);
        return *this;
    }

    P1& dbl()
    {
        blst_p1_double(&point, &point);
        return *this;
    }

    P1& mult(const Scalar& s)
    {
        blst_p1_mult(&point, &point, s.val.b, 255);
        return *this;
    }

    P1& cneg(bool flag)
    {
        blst_p1_cneg(&point, flag);
        return *this;
    }

    P1& neg()
    {
        return cneg(true);
    }
    // 返回新对象
    P1 operator-() const
    {
        P1 r = *this;
        r.neg();
        return r;
    }
    /* ---------- hash / sign ---------- */

    P1& sign_with(const Scalar& s)
    {
        blst_sign_pk_in_g2(&point, &point, &s.val);
        return *this;
    }

    P1& hash_to(
        std::span<const uint8_t> msg,
        std::span<const uint8_t> dst,
        std::span<const uint8_t> aug = {})
    {
        blst_hash_to_g1(
            &point,
            msg.data(), msg.size(),
            dst.data(), dst.size(),
            aug.data(), aug.size());
        return *this;
    }
    static P1 identity()
    {
        P1 p;
        memset(&p.point, 0, sizeof(p.point));
        return p;
    }
    static P1 from_hash(std::span<const uint8_t> msg, std::span<const uint8_t> dst = {})
    {
        P1 p;
        blst_hash_to_g1(
            &(p.point),
            msg.data(), msg.size(),
            dst.data(), dst.size(),
            {},{});
        return p;
    }


    friend class P1_Affine;
    operator const blst_p1*() const { return &point; }
};
}