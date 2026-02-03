extern "C" {
#include <blst.h>
}

#include "crypto/blst/Scalar.hpp"
#include "crypto/error.hpp"
#include "impl_common.hpp"
#include "utils.hpp"
#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <expected>
#include <openssl/rand.h>
#include <system_error>

namespace Honey::Crypto::bls {
static_assert(sizeof(Scalar) == sizeof(blst_scalar), "Scalar size mismatch with blst_scalar");

using impl::to_native;

Scalar Scalar::from_uint64(uint64_t v)
{
    Scalar s {};
    std::array<uint64_t, 4> tmp { v, 0, 0, 0 };
    blst_scalar_from_uint64(to_native<blst_scalar>(&s), tmp.data());
    return s;
}

std::expected<Scalar, std::error_code> Scalar::random(const char* DST)
{
    std::array<uint8_t, 32> ikm {};

    if (RAND_bytes(ikm.data(), sizeof(ikm)) != 1) {
        return std::unexpected(Error::BlstError);
    }

    // 生成 48 字节 (384 bits) 的均匀随机数，然后模 r
    // 这样做是为了消除模偏差 (modular bias)
    uint8_t out[48];
    blst_expand_message_xmd(out, sizeof(out),
        ikm.data(), ikm.size(),
        u8ptr(DST), std::strlen(DST));

    Scalar s;
    blst_scalar_from_be_bytes(to_native<blst_scalar>(&s), out, sizeof(out));
    return s;
}

std::array<uint8_t, Scalar::BYTE_LENGTH> Scalar::to_bytes() const
{
    std::array<uint8_t, BYTE_LENGTH> ret;
    blst_bendian_from_scalar(ret.data(), to_native<blst_scalar>(this));
    return ret;
}

std::expected<Scalar, std::error_code> Scalar::from_bytes(std::span<const uint8_t, 32> data)
{
    Scalar ret;
    blst_scalar_from_bendian(to_native<blst_scalar>(&ret), data.data());

    // Validate the scalar is in the field
    if (!blst_scalar_fr_check(to_native<blst_scalar>(&ret))) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    return ret;
}

} // namespace Honey::Crypto::bls
