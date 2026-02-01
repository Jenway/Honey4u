#pragma once

#include "blst_abi_config.hpp"
#include "crypto/types.hpp"
#include <array>
#include <cstddef>
#include <system_error>

namespace Honey::Crypto::bls {

class P2_Affine;
class P1;

// P1_Affine (G1 Affine Point)
//
// Size: 96 bytes (384 bits * 2 coordinates)
class P1_Affine {
public:
    static constexpr size_t BYTE_LENGTH = abi::blst_p1_affine_size;

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
    alignas(abi::blst_p1_affine_align) std::array<std::byte, abi::blst_p1_affine_size> storage;
};

} // namespace Honey::Crypto::bls
