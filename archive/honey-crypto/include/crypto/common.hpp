#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>

namespace Honey::Crypto {

using Byte = std::byte;
using BytesSpan = std::span<const Byte>;
using MutableBytesSpan = std::span<Byte>;
using Hash256 = std::array<Byte, 32>;

namespace Utils {
    Hash256 sha256(BytesSpan data);
}

// inline BytesSpan as_span(const std::string& s)
// {
//     // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
//     return { reinterpret_cast<const Byte*>(s.data()), s.size() };
// }
inline BytesSpan as_span(std::string_view s) noexcept
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return { reinterpret_cast<const Byte*>(s.data()), s.size() };
}

// =============================================================================
// Byte Casting Helpers (std::byte <-> uint8_t)
// =============================================================================

// 将 std::span<const std::byte> 转为 const uint8_t* (用于传给 blst 读)
inline const uint8_t* u8ptr(std::span<const std::byte> s)
{
    return reinterpret_cast<const uint8_t*>(s.data());
}

// 将 std::span<const uint8_t> 转为 const uint8_t* (重载，方便直接透传)
inline const uint8_t* u8ptr(std::span<const uint8_t> s)
{
    return s.data();
}

// 将 void* 转为 uint8_t* (通用转换)
inline const uint8_t* u8ptr(const void* ptr)
{
    return reinterpret_cast<const uint8_t*>(ptr);
}

// 可变版本 (用于传给 blst 写)
inline uint8_t* u8ptr(std::span<std::byte> s)
{
    return reinterpret_cast<uint8_t*>(s.data());
}

inline uint8_t* u8ptr(std::span<uint8_t> s)
{
    return s.data();
}
// 转换 std::byte* -> uint8_t* (C API 需要)
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

    // 或者支持 initializer_list 的版本（更灵活）
    template <size_t N>
    constexpr std::array<std::byte, N> make_bytes(std::initializer_list<uint8_t> l)
    {
        std::array<std::byte, N> res {};
        auto it = l.begin();
        for (size_t i = 0; i < N && it != l.end(); ++i, ++it) {
            res[i] = static_cast<std::byte>(*it);
        }
        return res;
    }
} // namespace Utils

} // namespace Honey::Crypto