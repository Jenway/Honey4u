#pragma once

#include "blst_abi_config.hpp"
#include "crypto/types.hpp"
#include <array>
#include <cstdint>
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

    static P2 generator();
    static P2 identity();
    static P2 from_hash(BytesSpan msg, BytesSpan dst = {});

    [[nodiscard]] bool equals(const P2&) const;

    void serialize(std::span<uint8_t, SERIALIZED_SIZE> out) const;
    void compress(std::span<uint8_t, COMPRESSED_SIZE> out) const;

    // Deserialization
    [[nodiscard]] static std::expected<P2, std::error_code>
    deserialize(std::span<const Byte, SERIALIZED_SIZE> data);
    [[nodiscard]] static std::expected<P2, std::error_code>
    uncompress(std::span<const Byte, COMPRESSED_SIZE> data);

private:
    alignas(abi::blst_p2_align) std::array<std::byte, abi::blst_p2_size> storage;
};

} // namespace Honey::Crypto::bls
