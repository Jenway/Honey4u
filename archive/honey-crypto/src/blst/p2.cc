extern "C" {
#include <blst.h>
}

#include "crypto/blst/P2.hpp"
#include "impl_common.hpp"
#include "utils.hpp"
#include <cstdint>
#include <cstring>
#include <span>

namespace Honey::Crypto::bls {

static_assert(sizeof(P2) == sizeof(blst_p2), "P2 size mismatch");
static_assert(alignof(P2) >= alignof(blst_p2), "P2 alignment mismatch");
static_assert(std::is_trivially_copyable_v<P2>);
static_assert(std::is_trivially_destructible_v<P2>);

using impl::to_native;

P2 P2::generator()
{
    P2 ret {};
    *to_native<blst_p2>(&ret) = *blst_p2_generator();
    return ret;
}

bool P2::equals(const P2& rhs) const
{
    return blst_p2_is_equal(
        to_native<blst_p2>(this),
        to_native<blst_p2>(&rhs));
}

P2 P2::identity()
{
    P2 ret {};
    std::memset(to_native<blst_p2>(&ret), 0, sizeof(blst_p2));
    return ret;
}

void P2::serialize(std::span<uint8_t, P2::SERIALIZED_SIZE> out) const
{
    blst_p2_serialize(out.data(), to_native<blst_p2>(this));
}

void P2::compress(std::span<uint8_t, P2::COMPRESSED_SIZE> out) const
{
    blst_p2_compress(out.data(), to_native<blst_p2>(this));
}

P2 P2::from_hash(BytesSpan msg, BytesSpan dst)
{
    P2 ret {};
    blst_hash_to_g2(
        to_native<blst_p2>(&ret),
        u8ptr(msg.data()), msg.size(),
        u8ptr(dst.data()), dst.size(),
        nullptr, 0);
    return ret;
}

std::expected<P2, std::error_code> P2::deserialize(std::span<const Byte, SERIALIZED_SIZE> data)
{
    blst_p2_affine affine;
    BLST_ERROR err = blst_p2_deserialize(
        &affine,
        reinterpret_cast<const uint8_t*>(data.data()));

    if (err != BLST_SUCCESS) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    P2 ret {};
    blst_p2_from_affine(
        to_native<blst_p2>(&ret),
        &affine);
    return ret;
}

std::expected<P2, std::error_code> P2::uncompress(std::span<const Byte, COMPRESSED_SIZE> data)
{
    blst_p2_affine affine;
    BLST_ERROR err = blst_p2_uncompress(
        &affine,
        reinterpret_cast<const uint8_t*>(data.data()));

    if (err != BLST_SUCCESS) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    P2 ret {};
    blst_p2_from_affine(
        to_native<blst_p2>(&ret),
        &affine);
    return ret;
}

} // namespace Honey::Crypto::bls
