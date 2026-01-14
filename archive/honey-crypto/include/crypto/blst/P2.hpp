#pragma once

#include <cassert>
#include <cstddef>
#include <cstring>
#include <expected>
#include <span>

extern "C" {
#include <blst.h>
}
#include "Scalar.hpp"

namespace Honey::Crypto::bls {

class P1;
class P2;
class P1_Affine;

class P2_Affine {
private:
    ::blst_p2_affine point;

    P2_Affine() = default;

    explicit P2_Affine(const blst_p2_affine& p)
        : point(p)
    {
    }

public:
    /* ---------- factories ---------- */

    static std::expected<P2_Affine, BLST_ERROR>
    from_bytes(std::span<const uint8_t> in)
    {
        blst_p2_affine p;
        BLST_ERROR err = blst_p2_deserialize(&p, in.data());
        if (err != BLST_SUCCESS)
            return std::unexpected(err);
        return P2_Affine(p);
    }

    static P2_Affine generator()
    {
        return P2_Affine(*blst_p2_affine_generator());
    }

    /* ---------- observers ---------- */

    P2_Affine dup() const { return *this; }

    void serialize(uint8_t out[192]) const
    {
        blst_p2_affine_serialize(out, &point);
    }

    void compress(uint8_t out[96]) const
    {
        blst_p2_affine_compress(out, &point);
    }

    bool on_curve() const { return blst_p2_affine_on_curve(&point); }
    bool in_group() const { return blst_p2_affine_in_g2(&point); }
    bool is_inf() const { return blst_p2_affine_is_inf(&point); }

    bool is_equal(const P2_Affine& p) const
    {
        return blst_p2_affine_is_equal(&point, &p.point);
    }

    BLST_ERROR core_verify(
        const P1_Affine& pk,
        bool hash_or_encode,
        std::span<const uint8_t> msg,
        std::span<const uint8_t> dst,
        std::span<const uint8_t> aug = {}) const;
    static P2_Affine from_P2(const P2& jac);

private:
    friend class P2;
    friend class PT;

public:
    operator const blst_p2_affine*() const { return &point; }
};

class P2 {
private:
    blst_p2 point;

    P2() = default;

    explicit P2(const blst_p2& p)
        : point(p)
    {
    }

public:
    /* ---------- factories ---------- */

    static P2 generator()
    {
        return P2(*blst_p2_generator());
    }

    static std::expected<P2, BLST_ERROR>
    from_bytes(std::span<const uint8_t> in)
    {
        blst_p2_affine a;
        BLST_ERROR err = blst_p2_deserialize(&a, in.data());
        if (err != BLST_SUCCESS)
            return std::unexpected(err);

        blst_p2 p;
        blst_p2_from_affine(&p, &a);
        return P2(p);
    }

    static P2 from_affine(const P2_Affine& a)
    {
        blst_p2 p;
        blst_p2_from_affine(&p, a);
        return P2(p);
    }

    /* ---------- observers ---------- */

    P2 dup() const { return *this; }

    bool on_curve() const { return blst_p2_on_curve(&point); }
    bool in_group() const { return blst_p2_in_g2(&point); }
    bool is_inf() const { return blst_p2_is_inf(&point); }

    bool is_equal(const P2& p) const
    {
        return blst_p2_is_equal(&point, &p.point);
    }

    void serialize(uint8_t out[192]) const
    {
        blst_p2_serialize(out, &point);
    }

    void compress(uint8_t out[96]) const
    {
        blst_p2_compress(out, &point);
    }

    /* ---------- mutators ---------- */

    P2& add(const P2& a)
    {
        blst_p2_add_or_double(&point, &point, a);
        return *this;
    }

    P2& add(const P2_Affine& a)
    {
        blst_p2_add_or_double_affine(&point, &point, a);
        return *this;
    }

    P2& dbl()
    {
        blst_p2_double(&point, &point);
        return *this;
    }

    P2& mult(const Scalar& s)
    {
        blst_p2_mult(&point, &point, s.val.b, 255);
        return *this;
    }

    P2& cneg(bool flag)
    {
        blst_p2_cneg(&point, flag);
        return *this;
    }

    P2& neg()
    {
        return cneg(true);
    }

    /* ---------- hash / sign ---------- */

    P2& sign_with(const Scalar& s)
    {
        blst_sign_pk_in_g1(&point, &point, &s.val);
        return *this;
    }

    P2& hash_to(
        std::span<const uint8_t> msg,
        std::span<const uint8_t> dst,
        std::span<const uint8_t> aug = {})
    {
        blst_hash_to_g2(
            &point,
            msg.data(), msg.size(),
            dst.data(), dst.size(),
            aug.data(), aug.size());
        return *this;
    }
    static P2 from_hash(std::span<const uint8_t> msg, std::span<const uint8_t> dst = {})
    {
        P2 p;
        blst_hash_to_g2(
            &(p.point),
            msg.data(), msg.size(),
            dst.data(), dst.size(),
            {}, {});
        return p;
    }

private:
    friend class P2_Affine;
    operator const blst_p2*() const { return &point; }
};
}