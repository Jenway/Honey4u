#pragma once

#include <array>
#include <vector>

#include "crypto/blst/P1.hpp"
#include "crypto/common.hpp"

#include "crypto/blst/P2.hpp"

struct evp_cipher_ctx_st;

namespace Honey::Crypto::Utils {

using P1 = bls::P1;
using P2 = bls::P2;

using AesKey = std::array<Byte, 32>; // AES-256 key


class AesContext {
public:
    AesContext();
    ~AesContext();

    // 禁用拷贝，支持移动
    AesContext(const AesContext&) = delete;
    AesContext& operator=(const AesContext&) = delete;
    AesContext(AesContext&& other) noexcept;
    AesContext& operator=(AesContext&& other) noexcept;

    // 获取内部指针供实现使用
    evp_cipher_ctx_st* get() { return ptr_; }

private:
    evp_cipher_ctx_st* ptr_ = nullptr;
};

Hash256 hashG(const P1& point);

// HashH: (G1, V) -> G2.
P2 hashH(const P1& u, BytesSpan v);

// XOR: Inputs are now flexible spans. Output is still vector as size is dynamic.
std::vector<Byte> xor_bytes(BytesSpan a, BytesSpan b);


auto aes_encrypt(AesContext& ctx, BytesSpan key, BytesSpan plaintext)
    -> std::expected<std::vector<Byte>, std::error_code>;

auto aes_decrypt(AesContext& ctx, BytesSpan key, BytesSpan ciphertext)
    -> std::expected<std::vector<Byte>, std::error_code>;

} // namespace Honey::Crypto::Utils