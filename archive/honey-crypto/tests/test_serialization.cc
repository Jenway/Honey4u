#include "crypto/blst/P1.hpp"
#include "crypto/blst/P2.hpp"
#include "crypto/blst/Scalar.hpp"
#include <cstring>
#include <gtest/gtest.h>

using namespace Honey::Crypto;
using namespace Honey::Crypto::bls;

TEST(SerializationTest, P1RoundTrip)
{
    // Generate a point
    P1 p1 = P1::generator();

    // Serialize
    auto serialized = p1.serialize();

    // Deserialize
    auto p1_back_result = P1::deserialize(serialized);
    ASSERT_TRUE(p1_back_result.has_value());

    EXPECT_EQ(p1, *p1_back_result);
}

TEST(SerializationTest, P1CompressRoundTrip)
{
    P1 p1 = P1::generator();

    // Compress
    auto compressed = p1.compress();

    // Uncompress
    auto p1_back_result = P1::uncompress(compressed);
    ASSERT_TRUE(p1_back_result.has_value());

    EXPECT_EQ(p1, *p1_back_result);
}

TEST(SerializationTest, P2RoundTrip)
{
    P2 p2 = P2::generator();

    // Serialize
    std::array<uint8_t, P2::SERIALIZED_SIZE> serialized;
    p2.serialize(serialized);

    // Deserialize (convert uint8_t to Byte)
    std::array<Byte, P2::SERIALIZED_SIZE> serialized_bytes;
    std::memcpy(serialized_bytes.data(), serialized.data(), P2::SERIALIZED_SIZE);

    auto p2_back_result = P2::deserialize(std::span(serialized_bytes));
    ASSERT_TRUE(p2_back_result.has_value());

    EXPECT_EQ(p2, *p2_back_result);
}

TEST(SerializationTest, P2CompressRoundTrip)
{
    P2 p2 = P2::generator();

    // Compress
    std::array<uint8_t, P2::COMPRESSED_SIZE> compressed;
    p2.compress(compressed);

    // Uncompress (convert uint8_t to Byte)
    std::array<Byte, P2::COMPRESSED_SIZE> compressed_bytes;
    std::memcpy(compressed_bytes.data(), compressed.data(), P2::COMPRESSED_SIZE);

    auto p2_back_result = P2::uncompress(std::span(compressed_bytes));
    ASSERT_TRUE(p2_back_result.has_value());

    EXPECT_EQ(p2, *p2_back_result);
}

TEST(SerializationTest, ScalarRoundTrip)
{
    Scalar s = Scalar::from_uint64(12345);

    // Serialize
    auto serialized = s.to_bytes();

    // Deserialize
    auto s_back_result = Scalar::from_bytes(serialized);
    ASSERT_TRUE(s_back_result.has_value());

    EXPECT_EQ(s, *s_back_result);
}

TEST(SerializationTest, ScalarRandomRoundTrip)
{
    auto s_result = Scalar::random();
    ASSERT_TRUE(s_result.has_value());
    Scalar s = *s_result;

    // Serialize
    auto serialized = s.to_bytes();

    // Deserialize
    auto s_back_result = Scalar::from_bytes(serialized);
    ASSERT_TRUE(s_back_result.has_value());

    EXPECT_EQ(s, *s_back_result);
}
