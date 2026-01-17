#pragma once

extern "C" {
#include <blst.h>
}

namespace Honey::Crypto::impl {

// =============================================================================
// Opaque Storage Casting Helpers (Wrapper* <-> BlstType*)
// =============================================================================

// 通用转换模板：将 Wrapper 指针转为 Blst 内部类型指针。
// 这里的魔法在于：P1, P2, Scalar 都是标准布局(Standard Layout)结构体，
// 且第一个成员就是数据数组。C++ 标准保证指向结构体的指针可以
// reinterpret_cast 为指向其第一个成员的指针。
// 这解决了 Scalar 用 .limbs 而 Point 用 .storage 的命名不一致问题。

template <typename BlstT, typename WrapperT>
inline BlstT* to_native(WrapperT* w)
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<BlstT*>(w);
}

template <typename BlstT, typename WrapperT>
inline const BlstT* to_native(const WrapperT* w)
{
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return reinterpret_cast<const BlstT*>(w);
}


}  // namespace Honey::Crypto::impl