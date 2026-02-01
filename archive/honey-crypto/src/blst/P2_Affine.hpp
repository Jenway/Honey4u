#pragma once

#include "blst_abi_config.hpp"
#include <array>

namespace Honey::Crypto::bls {

class P1_Affine;
class P2;

// P2_Affine (G2 Affine Point)
//
// Size: 192 bytes (96 bytes * 2 coordinates)
class P2_Affine {
public:
    static constexpr size_t ALIGN = abi::blst_p2_affine_align;
    static constexpr size_t BYTE_LENGTH = abi::blst_p2_affine_size;
    static constexpr size_t SERIALIZED_SIZE = abi::blst_p2_serialized_size;
    static constexpr size_t COMPRESSED_SIZE = abi::blst_p2_compressed_size;

    static P2_Affine generator();

    friend bool operator==(const P2_Affine& a, const P2_Affine& b) = default;

    static P2_Affine from_P2(const P2& jac);

private:
    alignas(ALIGN) std::array<std::byte, BYTE_LENGTH> storage;
};

} // namespace Honey::Crypto::bls
