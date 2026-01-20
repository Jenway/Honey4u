extern "C" {
#include <blst.h>
}

#include "crypto/blst/Scalar.hpp"
#include "crypto/common.hpp"
#include "crypto/error.hpp"
#include "impl_common.hpp"
#include <array>
#include <bit>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <expected>
#include <openssl/rand.h>
#include <system_error>

namespace Honey::Crypto::bls {
static_assert(sizeof(Scalar) == sizeof(blst_scalar), "Scalar size mismatch with blst_scalar");

using impl::to_native;

Scalar& Scalar::operator+=(const Scalar& other)
{
    assert(blst_sk_add_n_check(
               to_native<blst_scalar>(this),
               to_native<blst_scalar>(this),
               to_native<blst_scalar>(&other))
        && "blst add failed");
    return *this;
}

Scalar& Scalar::operator-=(const Scalar& other)
{
    assert(blst_sk_sub_n_check(to_native<blst_scalar>(this), to_native<blst_scalar>(this), to_native<blst_scalar>(&other)) && "blst sub failed");
    return *this;
}

Scalar& Scalar::operator*=(const Scalar& other)
{
    assert(blst_sk_mul_n_check(to_native<blst_scalar>(this), to_native<blst_scalar>(this), to_native<blst_scalar>(&other)) && "blst mul failed");
    return *this;
}

Scalar Scalar::operator-() const
{
    Scalar ret {};
    blst_scalar zero = { 0 };
    blst_sk_sub_n_check(
        to_native<blst_scalar>(&ret),
        &zero,
        to_native<blst_scalar>(this));
    return ret;
}

Scalar Scalar::inverse() const
{
    Scalar r = *this;
    blst_sk_inverse(to_native<blst_scalar>(&r), to_native<blst_scalar>(this));
    return r;
}

Scalar Scalar::from_uint64(uint64_t v)
{
    if constexpr (std::endian::native == std::endian::little) {
        return Scalar { { v, 0, 0, 0 } };
    } else {
        Scalar s {};
        std::array<uint64_t, 4> tmp { v, 0, 0, 0 };
        blst_scalar_from_uint64(to_native<blst_scalar>(&s), tmp.data());
        return s;
    }
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

} // namespace Honey::Crypto::bls
