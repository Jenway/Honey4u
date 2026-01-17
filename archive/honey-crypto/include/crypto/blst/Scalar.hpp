#pragma once

#include "crypto/common.hpp"
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <system_error>

namespace Honey::Crypto::bls {

struct Scalar {
    static constexpr size_t BIT_LENGTH = 255;
    static constexpr size_t BYTE_LENGTH = 32;
    // 256 位整数存储 (4 * 64 bits)
    std::array<uint64_t, 4> limbs {};

    Scalar& operator+=(const Scalar& other);
    Scalar& operator-=(const Scalar& other);
    Scalar& operator*=(const Scalar& other);

    Scalar operator-() const;
    [[nodiscard]] Scalar inverse() const;

    friend bool operator==(const Scalar&, const Scalar&) = default;

    static Scalar from_uint64(uint64_t v);
    static std::expected<Scalar, std::error_code> random(const char* DST = "HBFT_DEFAULT_SALT");

    static Scalar from_le_bytes(BytesSpan bytes);
    static Scalar from_be_bytes(BytesSpan bytes);
    void to_le_bytes(std::span<Byte, BYTE_LENGTH> out) const;
    void to_be_bytes(std::span<Byte, BYTE_LENGTH> out) const;
};

inline Scalar operator+(Scalar lhs, const Scalar& rhs)
{
    lhs += rhs;
    return lhs;
}

inline Scalar operator-(Scalar lhs, const Scalar& rhs)
{
    lhs -= rhs;
    return lhs;
}

inline Scalar operator*(Scalar lhs, const Scalar& rhs)
{
    lhs *= rhs;
    return lhs;
}

} // namespace Honey::Crypto::bls