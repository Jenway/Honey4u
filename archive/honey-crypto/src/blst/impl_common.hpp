#pragma once

#if defined(__cpp_lib_start_lifetime_as)
#include <memory>
#endif

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

} // namespace Honey::Crypto::impl
