#pragma once

#include <array>
#include <cassert>
#include <cstdint>
#include <expected>
#include <system_error>

namespace Honey::Crypto::bls {

struct Scalar {
    using limb_t = uint64_t;
    static constexpr size_t BIT_LENGTH = 255;
    static constexpr size_t BYTE_LENGTH = 32;
    static constexpr size_t LIMB_COUNT = BYTE_LENGTH / sizeof(limb_t);

    std::array<limb_t, LIMB_COUNT> limbs {};

    Scalar& operator+=(const Scalar& other);
    Scalar& operator-=(const Scalar& other);
    Scalar& operator*=(const Scalar& other);

    Scalar operator-() const;
    [[nodiscard]] Scalar inverse() const;

    friend bool operator==(const Scalar&, const Scalar&) = default;

    static Scalar from_uint64(uint64_t v);
    static std::expected<Scalar, std::error_code> random(const char* DST = "HBFT_DEFAULT_SALT");
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