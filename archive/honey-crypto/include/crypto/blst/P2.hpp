#pragma once

#include "crypto/blst/Scalar.hpp"
#include "crypto/common.hpp"
#include <array>
#include <cstdint>
#include <span>

namespace Honey::Crypto::bls {

class P1_Affine;
class P2;

// P2_Affine (G2 Affine Point)
// 
// Size: 192 bytes (96 bytes * 2 coordinates)
class P2_Affine {
public:
    using limb_t = uint64_t;
    static constexpr size_t BYTE_LENGTH = 192;
    static constexpr size_t LIMB_COUNT = BYTE_LENGTH / sizeof(limb_t);

    static constexpr size_t SERIALIZED_SIZE = 192;
    static constexpr size_t COMPRESSED_SIZE = 96;

    static P2_Affine generator();

    friend bool operator==(const P2_Affine& a, const P2_Affine& b) = default;

    static P2_Affine from_P2(const P2& jac);

    // 序列化
    void serialize(std::span<uint8_t, SERIALIZED_SIZE> out) const;
    void compress(std::span<uint8_t, COMPRESSED_SIZE> out) const;

private:
    std::array<limb_t, LIMB_COUNT> storage;
};

// P2 (G2 Jacobian Point)
//
// Size: 288 bytes (96 bytes * 3 coordinates)
class P2 {
public:
    using limb_t = uint64_t;
    static constexpr size_t BYTE_LENGTH = 288;
    static constexpr size_t LIMB_COUNT = BYTE_LENGTH / sizeof(limb_t);

    static constexpr size_t SERIALIZED_SIZE = 192;
    static constexpr size_t COMPRESSED_SIZE = 96;

    static P2 generator();
    static P2 identity();
    static P2 from_affine(const P2_Affine& a);
    static P2 from_hash(BytesSpan msg, BytesSpan dst = {});

    P2& add(const P2& a);
    P2& add(const P2_Affine& a);

    P2& mult(const Scalar& s);

    P2& neg();
    P2 operator-() const;

    friend bool operator==(const P2& a, const P2& b);

    void serialize(std::span<uint8_t, SERIALIZED_SIZE> out) const;
    void compress(std::span<uint8_t, COMPRESSED_SIZE> out) const;

    P2& sign_with(const Scalar& s);

    P2& hash_to(
        BytesSpan msg,
        BytesSpan dst,
        BytesSpan aug = {});

private:
    std::array<limb_t, LIMB_COUNT> storage;
};

} // namespace Honey::Crypto::bls