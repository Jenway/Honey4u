#pragma once

#include "crypto/types.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <openssl/evp.h>
#include <span>

namespace Honey::Crypto::impl {

using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype([](EVP_MD_CTX* ctx) {
    EVP_MD_CTX_free(ctx);
})>;

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

} // namespace Honey::Crypto::impl

// Backward compatibility or for convenience in .cc files
using Honey::Crypto::impl::u8ptr;
