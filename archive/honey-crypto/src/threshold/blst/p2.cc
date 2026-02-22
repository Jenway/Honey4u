extern "C" {
#include <blst.h>
}

#include "crypto/threshold/blst/P2.hpp"
#include "impl_common.hpp"
#include "ops.hpp"
#include <array>
#include <cstring>
#include <span>

namespace Honey::Crypto::bls {

static_assert(sizeof(P2) == sizeof(blst_p2), "P2 size mismatch");
static_assert(alignof(P2) >= alignof(blst_p2), "P2 alignment mismatch");
static_assert(std::is_trivially_copyable_v<P2>);
static_assert(std::is_trivially_destructible_v<P2>);

using impl::to_native;
using impl::u8ptr;

bool P2::equals(const P2& rhs) const
{
    return blst_p2_is_equal(to_native<blst_p2>(this), to_native<blst_p2>(&rhs));
}

std::array<std::byte, P2::SERIALIZED_SIZE> P2::serialize() const
{
    std::array<std::byte, P2::SERIALIZED_SIZE> buf {};
    blst_p2_serialize(reinterpret_cast<uint8_t*>(buf.data()), to_native<blst_p2>(this));
    return buf;
}

std::array<std::byte, P2::COMPRESSED_SIZE> P2::compress() const
{
    std::array<std::byte, P2::COMPRESSED_SIZE> buf {};
    blst_p2_compress(reinterpret_cast<uint8_t*>(buf.data()), to_native<blst_p2>(this));
    return buf;
}

std::expected<P2, std::error_code>
P2::deserialize(std::span<const Byte, SERIALIZED_SIZE> data)
{
    blst_p2_affine affine;
    BLST_ERROR err = blst_p2_deserialize(
        &affine, reinterpret_cast<const uint8_t*>(data.data()));

    if (err != BLST_SUCCESS) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    P2 ret {};
    blst_p2_from_affine(to_native<blst_p2>(&ret), &affine);
    return ret;
}

std::expected<P2, std::error_code>
P2::uncompress(std::span<const Byte, COMPRESSED_SIZE> data)
{
    blst_p2_affine affine;
    BLST_ERROR err = blst_p2_uncompress(
        &affine, reinterpret_cast<const uint8_t*>(data.data()));

    if (err != BLST_SUCCESS) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    P2 ret {};
    blst_p2_from_affine(to_native<blst_p2>(&ret), &affine);
    return ret;
}

} // namespace Honey::Crypto::bls

#if defined(HONEYBFT_INTERNAL_TESTS)
#include <doctest/doctest.h>

namespace Honey::Crypto::bls {

TEST_CASE("SerializationTest.P2RoundTrip")
{
    P2 p2 = ops::generator<P2>();

    auto serialized = p2.serialize();
    auto p2_back_result = P2::deserialize(serialized);
    REQUIRE(p2_back_result.has_value());

    CHECK(p2.equals(*p2_back_result));
}

TEST_CASE("SerializationTest.P2CompressRoundTrip")
{
    P2 p2 = ops::generator<P2>();

    auto compressed = p2.compress();
    auto p2_back_result = P2::uncompress(compressed);
    REQUIRE(p2_back_result.has_value());

    CHECK(p2.equals(*p2_back_result));
}

} // namespace Honey::Crypto::bls
#endif
