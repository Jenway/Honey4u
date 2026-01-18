#pragma once

#include "crypto/blst/P1.hpp"
#include "crypto/blst/P2.hpp"

#include <array>
#include <cstdint>

namespace Honey::Crypto::bls {

// PT (Fp12 Point / Target Group)
//
// Size: 576 bytes (48 bytes * 12 coefficients)
class PT {
public:
    using limb_t = uint64_t;
    static constexpr size_t BYTE_LENGTH = 576;
    static constexpr size_t LIMB_COUNT = BYTE_LENGTH / sizeof(limb_t);

    explicit PT(const P1_Affine& p);
    explicit PT(const P2_Affine& q);

    PT(const P2_Affine& q, const P1_Affine& p);
    PT(const P1_Affine& p, const P2_Affine& q);

    PT(const P2& q, const P1& p);
    PT(const P1& p, const P2& q);

    PT& final_exp();

    friend bool operator==(const PT& a, const PT& b) = default;

private:
    std::array<limb_t, LIMB_COUNT> storage {};
};

} // namespace Honey::Crypto::bls