#pragma once

#include "blst_abi_config.hpp"
#include <array>
#include <expected>
#include <span>
#include <system_error>

namespace Honey::Crypto::bls {

/// P2 (G2 Jacobian Point)
class P2 {
public:
    static constexpr size_t BYTE_LENGTH = abi::blst_p2_size;

    static constexpr size_t SERIALIZED_SIZE = abi::blst_p2_serialized_size;
    static constexpr size_t COMPRESSED_SIZE = abi::blst_p2_compressed_size;

    [[nodiscard]] bool equals(const P2&) const;

    [[nodiscard]] std::array<std::byte, SERIALIZED_SIZE> serialize() const;
    [[nodiscard]] std::array<std::byte, COMPRESSED_SIZE> compress() const;

    // Deserialization
    [[nodiscard]] static std::expected<P2, std::error_code>
    deserialize(std::span<const std::byte, SERIALIZED_SIZE> data);
    [[nodiscard]] static std::expected<P2, std::error_code>
    uncompress(std::span<const std::byte, COMPRESSED_SIZE> data);

private:
    alignas(abi::blst_p2_align) std::array<std::byte, abi::blst_p2_size> storage;
};

} // namespace Honey::Crypto::bls
