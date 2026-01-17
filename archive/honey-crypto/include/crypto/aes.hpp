#pragma once

#include "crypto/common.hpp"
#include <array>
#include <expected>
#include <system_error>
#include <vector>

struct evp_cipher_ctx_st;

namespace Honey::Crypto::Aes {

using AesKey = std::array<Byte, 32>; // AES-256 key

class Context {
public:
    Context();
    ~Context();

    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    Context(Context&& other) noexcept;
    Context& operator=(Context&& other) noexcept;

    evp_cipher_ctx_st* get() { return ptr_; }

private:
    evp_cipher_ctx_st* ptr_ = nullptr;
};

auto encrypt(Context& ctx, BytesSpan key, BytesSpan plaintext)
    -> std::expected<std::vector<Byte>, std::error_code>;

auto decrypt(Context& ctx, BytesSpan key, BytesSpan ciphertext)
    -> std::expected<std::vector<Byte>, std::error_code>;

} // namespace Honey::Crypto::Aes