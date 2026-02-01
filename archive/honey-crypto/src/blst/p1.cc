extern "C" {
#include <blst.h>
}

#include "P1_Affine.hpp"
#include "crypto/blst/P1.hpp"
#include "impl_common.hpp"
#include "impl_utils.hpp"
#include <array>
#include <cstring>

namespace Honey::Crypto::bls {
using impl::to_native;

static_assert(sizeof(P1) == sizeof(blst_p1), "P1 size mismatch");
static_assert(alignof(P1) >= alignof(blst_p1), "P1 alignment mismatch");

P1 P1::generator()
{
    P1 ret {};
    *to_native<blst_p1>(&ret) = *blst_p1_generator();
    return ret;
}

P1 P1::identity()
{
    P1 ret {};
    // blst 中全 0 代表无穷远点 (除了 Z 坐标需要注意，但 memset 0 通常是安全的初始状态)
    // 更正规的做法是设为无穷远
    // blst_p1 内部通常 Z=0 代表无穷远
    std::memset(to_native<blst_p1>(&ret), 0, sizeof(blst_p1));
    return ret;
}

/* Methods removed from public API and moved to ops.hpp/ops.cc */

P1 P1::from_hash(BytesSpan msg, BytesSpan dst)
{
    P1 ret {};
    blst_hash_to_g1(
        to_native<blst_p1>(&ret),
        u8ptr(msg.data()), msg.size(),
        u8ptr(dst.data()), dst.size(),
        nullptr, 0 // No aug
    );
    return ret;
}
[[nodiscard]] std::array<Byte, P1::SERIALIZED_SIZE> P1::serialize() const
{
    std::array<Byte, P1::SERIALIZED_SIZE> buf {};

    blst_p1_serialize(
        u8ptr(buf.data()),
        to_native<blst_p1>(this));
    return buf;
}

[[nodiscard]] std::array<Byte, P1::COMPRESSED_SIZE> P1::compress() const
{
    std::array<Byte, P1::COMPRESSED_SIZE> buf {};
    blst_p1_compress(
        u8ptr(buf.data()),
        to_native<blst_p1>(this));
    return buf;
};

std::expected<P1, std::error_code> P1::deserialize(std::span<const Byte, SERIALIZED_SIZE> data)
{
    P1_Affine affine;
    BLST_ERROR err = blst_p1_deserialize(
        to_native<blst_p1_affine>(&affine),
        reinterpret_cast<const uint8_t*>(data.data()));

    if (err != BLST_SUCCESS) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    P1 ret {};
    blst_p1_from_affine(
        to_native<blst_p1>(&ret),
        to_native<blst_p1_affine>(&affine));
    return ret;
}

std::expected<P1, std::error_code> P1::uncompress(std::span<const Byte, COMPRESSED_SIZE> data)
{
    P1_Affine affine;
    BLST_ERROR err = blst_p1_uncompress(
        to_native<blst_p1_affine>(&affine),
        reinterpret_cast<const uint8_t*>(data.data()));

    if (err != BLST_SUCCESS) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    P1 ret {};
    blst_p1_from_affine(
        to_native<blst_p1>(&ret),
        to_native<blst_p1_affine>(&affine));
    return ret;
}

} // namespace Honey::Crypto::bls
