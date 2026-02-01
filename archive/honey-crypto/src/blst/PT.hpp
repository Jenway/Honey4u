#pragma once

#include "blst_abi_config.hpp"
#include "crypto/blst/P1.hpp"
#include "crypto/blst/P2.hpp"

#include <array>
#include <cstdint>

namespace Honey::Crypto::bls {

class P1_Affine;
class P2_Affine;

// PT (Fp12 Point / Target Group)
//
// Size: 576 bytes (48 bytes * 12 coefficients)
class PT {
public:
    static constexpr size_t BYTE_LENGTH = abi::blst_fp12_size;

    explicit PT(const P1_Affine& p);
    explicit PT(const P2_Affine& q);

    PT(const P2_Affine& q, const P1_Affine& p);
    PT(const P1_Affine& p, const P2_Affine& q);

    PT(const P2& q, const P1& p);
    PT(const P1& p, const P2& q);

    PT& final_exp();

    friend bool operator==(const PT& a, const PT& b) = default;

private:
    alignas(abi::blst_fp12_align) std::array<std::byte, abi::blst_fp12_size> storage {};
};

static_assert(sizeof(PT) == abi::blst_fp12_size, "PT size mismatch");
static_assert(alignof(PT) == abi::blst_fp12_align, "PT alignment mismatch");

} // namespace Honey::Crypto::bls
