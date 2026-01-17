#pragma once

#include <cassert>
#include <cstddef>
#include <cstring>
#include <expected>
#include <openssl/rand.h>
#include <span>
#include <system_error>

extern "C" {
#include <blst.h>
}

namespace Honey::Crypto::bls {

struct Scalar {
    blst_scalar val {};

    friend class P1;
    friend class P2;

    static Scalar from_le_bytes(std::span<const std::byte> bytes)
    {
        Scalar s;
        blst_scalar_from_le_bytes(
            &s.val,
            reinterpret_cast<const uint8_t*>(bytes.data()),
            bytes.size());
        return s;
    }

    static Scalar from_be_bytes(std::span<const std::byte> bytes)
    {
        Scalar s;
        blst_scalar_from_be_bytes(
            &s.val,
            reinterpret_cast<const uint8_t*>(bytes.data()),
            bytes.size());
        return s;
    }

    static Scalar from_uint64(uint64_t v)
    {
        Scalar s;
        std::byte buf[32] = {};

        // 手动写入低 8 字节为 little-endian
        buf[0] = static_cast<std::byte>(v & 0xFF);
        buf[1] = static_cast<std::byte>((v >> 8) & 0xFF);
        buf[2] = static_cast<std::byte>((v >> 16) & 0xFF);
        buf[3] = static_cast<std::byte>((v >> 24) & 0xFF);
        buf[4] = static_cast<std::byte>((v >> 32) & 0xFF);
        buf[5] = static_cast<std::byte>((v >> 40) & 0xFF);
        buf[6] = static_cast<std::byte>((v >> 48) & 0xFF);
        buf[7] = static_cast<std::byte>((v >> 56) & 0xFF);

        blst_scalar_from_le_bytes(&s.val, reinterpret_cast<const uint8_t*>(buf), sizeof(buf));
        return s;
    }

    static std::expected<Scalar, std::error_code> random(const char* DST = "HBFT_DEFAULT_SALT")
    {
        uint8_t ikm[32];
        if (RAND_bytes(ikm, sizeof(ikm)) != 1) {
            return std::unexpected(std::make_error_code(std::errc::io_error));
        }

        uint8_t out[48];
        blst_expand_message_xmd(out, sizeof(out),
            ikm, sizeof(ikm),
            reinterpret_cast<const uint8_t*>(DST), std::strlen(DST));

        Scalar s;
        blst_scalar_from_be_bytes(&s.val, out, sizeof(out));
        return s;
    }

    // ===== serialization =====

    void to_le_bytes(std::span<std::byte, 32> out) const
    {
        blst_lendian_from_scalar(
            reinterpret_cast<uint8_t*>(out.data()),
            &val);
    }

    void to_be_bytes(std::span<std::byte, 32> out) const
    {
        blst_bendian_from_scalar(
            reinterpret_cast<uint8_t*>(out.data()),
            &val);
    }

    // ===== arithmetic (in-place) =====

    Scalar& operator+=(const Scalar& other)
    {
        assert(blst_sk_add_n_check(&val, &val, &other.val) && "blst add failed");
        return *this;
    }

    Scalar& operator-=(const Scalar& other)
    {
        assert(blst_sk_sub_n_check(&val, &val, &other.val) && "blst sub failed");
        return *this;
    }

    Scalar& operator*=(const Scalar& other)
    {
        assert(blst_sk_mul_n_check(&val, &val, &other.val) && "blst mul failed");
        return *this;
    }

    // ===== arithmetic (value) =====

    friend Scalar operator+(Scalar a, const Scalar& b)
    {
        return a += b;
    }

    friend Scalar operator-(Scalar a, const Scalar& b)
    {
        return a -= b;
    }

    friend Scalar operator*(Scalar a, const Scalar& b)
    {
        return a *= b;
    }

    Scalar operator-() const
    {
        return Scalar::from_uint64(0) - *this;
    }

    // ===== field operations =====

    Scalar inverse() const
    {
        Scalar r = *this;
        blst_sk_inverse(&r.val, &r.val);
        return r;
    }

    // ===== comparison =====

    bool operator==(const Scalar& other) const
    {
        return std::memcmp(&val, &other.val, sizeof(val)) == 0;
    }

    bool operator!=(const Scalar& other) const { return !(*this == other); }
};

} // namespace Honey::Crypto::bls
