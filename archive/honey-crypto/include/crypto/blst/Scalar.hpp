#pragma once

#include "blst_abi_config.hpp"
#include <array>
#include <cassert>
#include <cstdint>
#include <expected>
#include <span>
#include <system_error>

namespace Honey::Crypto::bls {

struct Scalar {
    static constexpr size_t ALIGN = abi::blst_scalar_align;
    static constexpr size_t BIT_LENGTH = 255;
    static constexpr size_t BYTE_LENGTH = abi::blst_scalar_size;
    static constexpr size_t SERIALIZED_SIZE = abi::blst_scalar_serialized_size;

    alignas(ALIGN) std::array<std::byte, abi::blst_scalar_size> limbs {};

    friend bool operator==(const Scalar&, const Scalar&) = default;

    static Scalar from_uint64(uint64_t v);
    static std::expected<Scalar, std::error_code> random(const char* DST = "HBFT_DEFAULT_SALT");

    [[nodiscard]] std::array<uint8_t, BYTE_LENGTH> to_bytes() const;
    [[nodiscard]] static std::expected<Scalar, std::error_code>
    from_bytes(std::span<const uint8_t, SERIALIZED_SIZE> data);
};

static_assert(sizeof(Scalar) == abi::blst_scalar_size, "Scalar size mismatch");
static_assert(alignof(Scalar) == abi::blst_scalar_align, "Scalar alignment mismatch");

} // namespace Honey::Crypto::bls
