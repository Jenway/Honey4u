#pragma once

#include <cassert>
#include <cstddef>
#include <cstring>
#include <span>

extern "C" {
#include <blst.h>
}
#include "Scalar.hpp"

#include "P1.hpp"
#include "P2.hpp"

namespace Honey::Crypto::bls
{

class PT {
private:
    blst_fp12 value;

    PT(const blst_fp12* v) { value = *v; }

public:
    PT(const P1_Affine& p) { blst_aggregated_in_g1(&value, p); }
    PT(const P2_Affine& q) { blst_aggregated_in_g2(&value, q); }
    PT(const P2_Affine& q, const P1_Affine& p)
    {
        blst_miller_loop(&value, q, p);
    }
    PT(const P1_Affine& p, const P2_Affine& q)
        : PT(q, p)
    {
    }
    PT(const P2& q, const P1& p)
    {
        blst_miller_loop(&value, P2_Affine::from_P2(q), P1_Affine::from_P1(p));
    }
    PT(const P1& p, const P2& q)
        : PT(q, p)
    {
    }

    PT dup() const { return *this; }
    bool is_one() const { return blst_fp12_is_one(&value); }
    bool is_equal(const PT& p) const
    {
        return blst_fp12_is_equal(&value, p);
    }
    PT* sqr()
    {
        blst_fp12_sqr(&value, &value);
        return this;
    }
    PT* mul(const PT& p)
    {
        blst_fp12_mul(&value, &value, p);
        return this;
    }
    PT* final_exp()
    {
        blst_final_exp(&value, &value);
        return this;
    }
    bool in_group() const { return blst_fp12_in_group(&value); }
    void to_bendian(byte out[48 * 12]) const
    {
        blst_bendian_from_fp12(out, &value);
    }

    static bool finalverify(const PT& gt1, const PT& gt2)
    {
        return blst_fp12_finalverify(gt1, gt2);
    }
    static PT one() { return PT(blst_fp12_one()); }

private:
    friend class Pairing;
    operator const blst_fp12*() const { return &value; }
};
}