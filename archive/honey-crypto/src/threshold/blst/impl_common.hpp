#pragma once

#if defined(__cpp_lib_start_lifetime_as)
#include <memory>
#endif
#include <cstdint>
#include <span>

namespace Honey::Crypto::impl {

// =============================================================================
// Opaque Storage Casting Helpers (Wrapper* <-> BlstType*)
// =============================================================================

template <typename BlstT, typename WrapperT>
inline BlstT* to_native(WrapperT* w)
{

#if defined(__cpp_lib_start_lifetime_as)
    return std::start_lifetime_as<BlstT>(reinterpret_cast<void*>(w));
#else
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<BlstT*>(w);
#endif
}

template <typename BlstT, typename WrapperT>
inline const BlstT* to_native(const WrapperT* w)
{
#if defined(__cpp_lib_start_lifetime_as)
    return std::start_lifetime_as<const BlstT>(reinterpret_cast<const void*>(w));
#else
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<const BlstT*>(w);
#endif
}

// ---------------------------------------------------------------------------
// Low-level byte-pointer cast helpers
// ---------------------------------------------------------------------------

inline const uint8_t* u8ptr(std::span<const std::byte> s)
{
    return reinterpret_cast<const uint8_t*>(s.data());
}

inline const uint8_t* u8ptr(std::span<const uint8_t> s) { return s.data(); }

inline const uint8_t* u8ptr(const void* ptr)
{
    return reinterpret_cast<const uint8_t*>(ptr);
}

inline uint8_t* u8ptr(std::span<std::byte> s)
{
    return reinterpret_cast<uint8_t*>(s.data());
}

inline uint8_t* u8ptr(std::span<uint8_t> s) { return s.data(); }

inline const uint8_t* u8ptr(const std::byte* ptr)
{
    return reinterpret_cast<const uint8_t*>(ptr);
}

inline uint8_t* u8ptr(std::byte* ptr)
{
    return reinterpret_cast<uint8_t*>(ptr);
}

} // namespace Honey::Crypto::impl
