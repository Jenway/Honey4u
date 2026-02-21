#include "crypto/aes.hpp"
#include "crypto/error.hpp"
#include "utils.hpp"
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

static constexpr size_t BLOCK_SIZE = 16;
static constexpr size_t IV_SIZE = 16;
static constexpr size_t PADDING_SIZE = 16;

auto encrypt(Context& ctx, const AesKey& key, BytesSpan plaintext)
    -> std::expected<std::vector<Byte>, std::error_code>
{
    auto* native_ctx = ctx.get();

    // 生成随机 IV
    std::array<Byte, IV_SIZE> iv {};
    if (RAND_bytes(u8ptr(iv.data()), IV_SIZE) != 1) {
        return std::unexpected(std::make_error_code(std::errc::io_error));
    }

    // 预留空间: IV(16) + Plaintext + Padding(最多16)
    std::vector<Byte> ciphertext(IV_SIZE + plaintext.size() + PADDING_SIZE);
    int len = 0;
    int ciphertext_len = 0;

    // 初始化加密操作 (复用上下文时，Init 会重置内部状态)
    if (1 != EVP_EncryptInit_ex(native_ctx, EVP_aes_256_cbc(), nullptr, u8ptr(key.data()), u8ptr(iv.data()))) {
        return std::unexpected(make_error_code(Error::OpenSSLError));
    }

    // 从第 16 字节开始写密文，前 16 字节留给 IV
    uint8_t* p_out = u8ptr(ciphertext.data()) + 16;

    if (1 != EVP_EncryptUpdate(native_ctx, p_out, &len, u8ptr(plaintext), static_cast<int>(plaintext.size()))) {
        return std::unexpected(make_error_code(Error::OpenSSLError));
    }
    ciphertext_len += len;

    if (1 != EVP_EncryptFinal_ex(native_ctx, p_out + len, &len)) {
        return std::unexpected(make_error_code(Error::OpenSSLError));
    }
    ciphertext_len += len;

    // 将 IV 拷贝到头部
    std::memcpy(ciphertext.data(), iv.data(), IV_SIZE);
    ciphertext.resize(IV_SIZE + ciphertext_len);

    return ciphertext;
}

auto decrypt(Context& ctx, const AesKey& key, BytesSpan ciphertext)
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

    if (1 != EVP_DecryptInit_ex(native_ctx, EVP_aes_256_cbc(), nullptr, u8ptr(key.data()), u8ptr(iv))) {
        return std::unexpected(make_error_code(Error::OpenSSLError));
    }

    if (1 != EVP_DecryptUpdate(native_ctx, u8ptr(plaintext.data()), &len, u8ptr(data), static_cast<int>(data.size()))) {
        return std::unexpected(make_error_code(Error::OpenSSLError));
    }
    plaintext_len += len;

    // Final 失败通常意味着 Padding 校验失败或 Key 错误
    if (1 != EVP_DecryptFinal_ex(native_ctx, u8ptr(plaintext.data()) + len, &len)) {
        // 解密失败（数据损坏或密钥错）
        return std::unexpected(make_error_code(Error::OpenSSLError));
    }
    plaintext_len += len;

    plaintext.resize(plaintext_len);
    return plaintext;
}
} // namespace Honey::Crypto::Aes

// =============================================================================
// 测试
// =============================================================================
#ifndef DOCTEST_CONFIG_DISABLE
#include <doctest/doctest.h>

namespace Honey::Crypto::Aes {
AesKey test_key {};

TEST_CASE("AES-256-CBC Encryption/Decryption Roundtrip")
{
    Context ctx;

    std::string_view message = "Some secret message to encrypt";
    BytesSpan plaintext { reinterpret_cast<const Byte*>(message.data()), message.size() };

    auto encrypt_res = encrypt(ctx, test_key, plaintext);

    REQUIRE(encrypt_res.has_value());
    auto ciphertext = encrypt_res.value();

    CHECK(ciphertext.size() > plaintext.size()); // 密文应包含 IV 和 Padding
    CHECK(ciphertext.size() % 16 == 0); // CBC 密文长度应是 BlockSize 的倍数

    auto decrypt_res = decrypt(ctx, test_key, ciphertext);

    REQUIRE(decrypt_res.has_value());
    auto decrypted_text = decrypt_res.value();

    CHECK(decrypted_text.size() == plaintext.size());
    CHECK(std::memcmp(decrypted_text.data(), plaintext.data(), plaintext.size()) == 0);
}

TEST_CASE("AES Error Handling")
{
    Context ctx;

    SUBCASE("Short ciphertext should return error")
    {
        std::vector<Byte> tiny_ciphertext(10, Byte { 0 });
        auto res = decrypt(ctx, test_key, tiny_ciphertext);
        CHECK(!res.has_value());
        CHECK(res.error() == std::errc::invalid_argument);
    }
}
} // namespace Honey::Crypto::Aes

#endif
