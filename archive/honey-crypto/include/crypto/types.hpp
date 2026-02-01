#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>
#include <vector>

namespace Honey::Crypto {

using Byte = std::byte;
using BytesSpan = std::span<const Byte>;
using MutableBytesSpan = std::span<Byte>;
using Hash256 = std::array<Byte, 32>;

inline BytesSpan as_span(std::string_view s) noexcept
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return { reinterpret_cast<const Byte*>(s.data()), s.size() };
}

inline BytesSpan as_span(std::span<const uint8_t> s) noexcept
{
    return { reinterpret_cast<const Byte*>(s.data()), s.size() };
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
