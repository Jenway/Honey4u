extern "C" {
#include <blst.h>
}

#include "crypto/threshold/blst/P1.hpp"
#include "impl_common.hpp"
#include "ops.hpp"
#include <array>
#include <cstring>

namespace Honey::Crypto::bls {

static_assert(sizeof(P1) == sizeof(blst_p1), "P1 size mismatch");
static_assert(alignof(P1) >= alignof(blst_p1), "P1 alignment mismatch");
static_assert(std::is_trivially_copyable_v<P1>);
static_assert(std::is_trivially_destructible_v<P1>);

using impl::to_native;
using impl::u8ptr;
[[nodiscard]] std::array<Byte, P1::SERIALIZED_SIZE> P1::serialize() const
{
    std::array<Byte, P1::SERIALIZED_SIZE> buf {};

    blst_p1_serialize(u8ptr(buf.data()), to_native<blst_p1>(this));
    return buf;
}

[[nodiscard]] std::array<Byte, P1::COMPRESSED_SIZE> P1::compress() const
{
    std::array<Byte, P1::COMPRESSED_SIZE> buf {};
    blst_p1_compress(u8ptr(buf.data()), to_native<blst_p1>(this));
    return buf;
};

std::expected<P1, std::error_code>
P1::deserialize(std::span<const Byte, SERIALIZED_SIZE> data)
{
    blst_p1_affine affine;
    BLST_ERROR err = blst_p1_deserialize(
        &affine, reinterpret_cast<const uint8_t*>(data.data()));

    if (err != BLST_SUCCESS) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    P1 ret {};
    blst_p1_from_affine(to_native<blst_p1>(&ret), &affine);
    return ret;
}

std::expected<P1, std::error_code>
P1::uncompress(std::span<const Byte, COMPRESSED_SIZE> data)
{
    // P1_Affine affine;
    blst_p1_affine affine;

    BLST_ERROR err = blst_p1_uncompress(
        &affine, reinterpret_cast<const uint8_t*>(data.data()));

    if (err != BLST_SUCCESS) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    P1 ret {};
    blst_p1_from_affine(to_native<blst_p1>(&ret), &affine);
    return ret;
}

bool P1::equals(const P1& others) const
{
    return blst_p1_is_equal(to_native<blst_p1>(this),
        to_native<blst_p1>(&others));
}

} // namespace Honey::Crypto::bls

#if defined(HONEYBFT_INTERNAL_TESTS)
#include <doctest/doctest.h>

namespace Honey::Crypto::bls {

TEST_CASE("SerializationTest.P1RoundTrip")
{
    P1 p1 = ops::generator<P1>();

    auto serialized = p1.serialize();

    auto p1_back_result = P1::deserialize(serialized);
    REQUIRE(p1_back_result.has_value());

    CHECK(p1.equals(*p1_back_result));
}

TEST_CASE("SerializationTest.P1CompressRoundTrip")
{
    P1 p1 = ops::generator<P1>();

    auto compressed = p1.compress();

    auto p1_back_result = P1::uncompress(compressed);
    REQUIRE(p1_back_result.has_value());

    CHECK(p1.equals(*p1_back_result));
}

} // namespace Honey::Crypto::bls
#endif
