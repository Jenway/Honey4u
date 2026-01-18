#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace Honey::Crypto {

using Byte = std::byte;
using BytesSpan = std::span<const Byte>;
using MutableBytesSpan = std::span<Byte>;
using Hash256 = std::array<Byte, 32>;

namespace Utils {
    Hash256 sha256(BytesSpan data);
} // namespace Utils

inline BytesSpan as_span(std::string_view s) noexcept
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return { reinterpret_cast<const Byte*>(s.data()), s.size() };
}

inline const uint8_t* u8ptr(std::span<const std::byte> s)
{
    return reinterpret_cast<const uint8_t*>(s.data());
}

inline const uint8_t* u8ptr(std::span<const uint8_t> s)
{
    return s.data();
}

inline const uint8_t* u8ptr(const void* ptr)
{
    return reinterpret_cast<const uint8_t*>(ptr);
}

inline uint8_t* u8ptr(std::span<std::byte> s)
{
    return reinterpret_cast<uint8_t*>(s.data());
}

inline uint8_t* u8ptr(std::span<uint8_t> s)
{
    return s.data();
}

inline const uint8_t* u8ptr(const std::byte* ptr)
{
    return reinterpret_cast<const uint8_t*>(ptr);
}

inline uint8_t* u8ptr(std::byte* ptr)
{
    return reinterpret_cast<uint8_t*>(ptr);
}

namespace Utils {

    template <size_t N>
    constexpr std::array<std::byte, N> make_bytes(const uint8_t (&arr)[N])
    {
        std::array<std::byte, N> res {};
        for (size_t i = 0; i < N; ++i) {
            res[i] = static_cast<std::byte>(arr[i]);
        }
        return res;
    }

    template <size_t N>
    constexpr std::array<std::byte, N> make_bytes(std::initializer_list<uint8_t> l)
    {
        std::array<std::byte, N> res {};
        const auto* it = l.begin();
        for (size_t i = 0; i < N && it != l.end(); ++i, ++it) {
            res[i] = static_cast<std::byte>(*it);
        }
        return res;
    }
} // namespace Utils

} // namespace Honey::Crypto