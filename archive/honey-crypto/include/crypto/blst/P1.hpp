#pragma once

#include "blst_abi_config.hpp"
#include <array>
#include <crypto/types.hpp>
#include <cstddef>
#include <expected>
#include <system_error>

namespace Honey::Crypto::bls {

class P1_Affine;

/// P1 (G1 Jacobian Point)
class P1 {
public:
    static constexpr size_t ALIGN = abi::blst_p1_align;
    static constexpr size_t BYTE_LENGTH = abi::blst_p1_size;
    static constexpr size_t SERIALIZED_SIZE = abi::blst_p1_serialized_size;
    static constexpr size_t COMPRESSED_SIZE = abi::blst_p1_compressed_size;

    static P1 generator();
    static P1 identity(); // 无穷远点/零点
    static P1 from_hash(BytesSpan msg, BytesSpan dst = {});

    [[nodiscard]] bool equals(const P1&) const;

    [[nodiscard]] std::array<Byte, SERIALIZED_SIZE> serialize() const;
    [[nodiscard]] std::array<Byte, COMPRESSED_SIZE> compress() const;

    [[nodiscard]] static std::expected<P1, std::error_code>
    deserialize(std::span<const Byte, SERIALIZED_SIZE> data);
    [[nodiscard]] static std::expected<P1, std::error_code>
    uncompress(std::span<const Byte, COMPRESSED_SIZE> data);

private:
    alignas(ALIGN) std::array<std::byte, BYTE_LENGTH> storage;
};

} // namespace Honey::Crypto::bls
