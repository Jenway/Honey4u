#include "crypto/aes.hpp"
#include "crypto/common.hpp"
#include <cstdint>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace Honey::Crypto::Aes {

Context::Context()
    : ptr_(EVP_CIPHER_CTX_new())
{
}

Context::~Context()
{
    if (ptr_ != nullptr)
        EVP_CIPHER_CTX_free(ptr_);
}

Context::Context(Context&& other) noexcept
    : ptr_(other.ptr_)
{
    other.ptr_ = nullptr;
}

Context& Context::operator=(Context&& other) noexcept
{
    if (this != &other) {
        if (ptr_ != nullptr)
            EVP_CIPHER_CTX_free(ptr_);
        ptr_ = other.ptr_;
        other.ptr_ = nullptr;
    }
    return *this;
}

auto encrypt(Context& ctx, BytesSpan key, BytesSpan plaintext)
    -> std::expected<std::vector<Byte>, std::error_code>
{
    if (key.size() != 32) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }
    auto* native_ctx = ctx.get();

    // 生成随机 IV
    std::vector<Byte> iv(16);
    if (RAND_bytes(u8ptr(iv.data()), 16) != 1) {
        return std::unexpected(std::make_error_code(std::errc::io_error));
    }

    // 预留空间: IV(16) + Plaintext + Padding(最多16)
    std::vector<Byte> ciphertext(16 + plaintext.size() + 16);
    int len = 0;
    int ciphertext_len = 0;

    // 初始化加密操作 (复用上下文时，Init 会重置内部状态)
    if (1 != EVP_EncryptInit_ex(native_ctx, EVP_aes_256_cbc(), nullptr, u8ptr(key.data()), u8ptr(iv.data()))) {
        return std::unexpected(std::make_error_code(std::errc::protocol_error));
    }

    // 从第 16 字节开始写密文，前 16 字节留给 IV
    uint8_t* p_out = u8ptr(ciphertext.data()) + 16;

    if (1 != EVP_EncryptUpdate(native_ctx, p_out, &len, u8ptr(plaintext), static_cast<int>(plaintext.size()))) {
        return std::unexpected(std::make_error_code(std::errc::protocol_error));
    }
    ciphertext_len += len;

    if (1 != EVP_EncryptFinal_ex(native_ctx, p_out + len, &len)) {
        return std::unexpected(std::make_error_code(std::errc::protocol_error));
    }
    ciphertext_len += len;

    // 将 IV 拷贝到头部
    std::memcpy(ciphertext.data(), iv.data(), 16);
    ciphertext.resize(16 + ciphertext_len);

    return ciphertext;
}

auto decrypt(Context& ctx, BytesSpan key, BytesSpan ciphertext)
    -> std::expected<std::vector<Byte>, std::error_code>
{
    if (key.size() != 32 || ciphertext.size() < 16) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    auto* native_ctx = ctx.get();

    // 提取 IV 和 密文数据
    BytesSpan iv = ciphertext.subspan(0, 16);
    BytesSpan data = ciphertext.subspan(16);

    std::vector<Byte> plaintext(data.size());
    int len = 0;
    int plaintext_len = 0;

    if (1 != EVP_DecryptInit_ex(native_ctx, EVP_aes_256_cbc(), nullptr, u8ptr(key), u8ptr(iv))) {
        return std::unexpected(std::make_error_code(std::errc::protocol_error));
    }

    if (1 != EVP_DecryptUpdate(native_ctx, u8ptr(plaintext.data()), &len, u8ptr(data), static_cast<int>(data.size()))) {
        return std::unexpected(std::make_error_code(std::errc::protocol_error));
    }
    plaintext_len += len;

    // Final 失败通常意味着 Padding 校验失败或 Key 错误
    if (1 != EVP_DecryptFinal_ex(native_ctx, u8ptr(plaintext.data()) + len, &len)) {
        // 解密失败（数据损坏或密钥错）在 std::errc 中最接近的是 bad_message
        return std::unexpected(std::make_error_code(std::errc::bad_message));
    }
    plaintext_len += len;

    plaintext.resize(plaintext_len);
    return plaintext;
}
}  // namespace Honey::Crypto::Aes
