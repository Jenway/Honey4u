#pragma once

#include "crypto/blst/Scalar.hpp"
#include "crypto/common.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <system_error>

namespace Honey::Crypto::bls {

class P2_Affine;
class P1;

// P1_Affine (G1 Affine Point)
//
// Size: 96 bytes (384 bits * 2 coordinates)
class P1_Affine {
public:
    using limb_t = uint64_t;
    static constexpr size_t BYTE_LENGTH = 96;
    static constexpr size_t LIMB_COUNT = BYTE_LENGTH / sizeof(limb_t);

    static P1_Affine generator();
    static P1_Affine from_P1(const P1& jac);

    friend bool operator==(const P1_Affine& a, const P1_Affine& b) = default;

    [[nodiscard]] std::error_code core_verify(
        const P2_Affine& pk,
        bool hash_or_encode,
        BytesSpan msg,
        BytesSpan dst,
        BytesSpan aug = {}) const;

private:
    std::array<limb_t, LIMB_COUNT> storage;
};

// P1 (G1 Jacobian Point)
//
// Size: 144 bytes (384 bits * 3 coordinates)
class P1 {
public:
    using limb_t = uint64_t;
    static constexpr size_t BYTE_LENGTH = 144;
    static constexpr size_t LIMB_COUNT = BYTE_LENGTH / sizeof(limb_t);
    static constexpr size_t SERIALIZED_SIZE = 96;
    static constexpr size_t COMPRESSED_SIZE = 48;

    static P1 generator();
    static P1 identity(); // 无穷远点/零点
    static P1 from_affine(const P1_Affine& a);
    static P1 from_hash(BytesSpan msg, BytesSpan dst = {});

    P1& add(const P1& a);
    P1& add(const P1_Affine& a);

    P1& mult(const Scalar& s);

    P1& neg();
    P1 operator-() const;

    friend bool operator==(const P1& a, const P1& b);

    P1& sign_with(const Scalar& s);

    P1& hash_to(
        BytesSpan msg,
        BytesSpan dst,
        BytesSpan aug = {});

    [[nodiscard]] std::array<Byte, SERIALIZED_SIZE> serialize() const;
    [[nodiscard]] std::array<Byte, COMPRESSED_SIZE> compress() const;

private:
    // 18 * 8 = 144 bytes
    std::array<limb_t, LIMB_COUNT> storage;
};

} // namespace Honey::Crypto::bls