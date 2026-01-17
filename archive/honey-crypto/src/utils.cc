#include "crypto/threshold/utils.hpp"
#include "crypto/common.hpp"
#include <blst.h>
#include <cstddef>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/types.h>
#include <span>
#include <stdexcept>
#include <string>

namespace Honey::Crypto::Utils {

Hash256 sha256(BytesSpan data)
{
    Hash256 hash;
    SHA256(
        u8ptr(data.data()),
        data.size(),
        u8ptr(hash.data()));
    return hash;
}

Hash256 hashG(const P1& point)
{
    return sha256(point.compress());
}

// HashH: (G1, V) -> G2.
P2 hashH(const P1& u, BytesSpan v)
{
    auto u_bytes = u.compress();

    std::vector<Byte> msg;
    msg.reserve(u_bytes.size() + v.size());

    // Build the message to be hashed
    msg.insert(msg.end(), u_bytes.begin(), u_bytes.end());
    msg.insert(msg.end(), v.begin(), v.end());

    static const std::string DST = "TPKE_HASH_H_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

    auto h = P2::from_hash(msg, as_span(DST));
    return h;
}

// XOR: Inputs are now flexible spans. Output is still vector as size is dynamic.
std::vector<Byte> xor_bytes(BytesSpan a, BytesSpan b)
{
    if (a.size() != b.size()) {
        throw std::invalid_argument("XOR length mismatch");
    }
    std::vector<Byte> res(a.size());
    for (size_t i = 0; i < a.size(); ++i) {
        res[i] = a[i] ^ b[i];
    }
    return res;
}

auto aes_encrypt(AesContext& ctx, BytesSpan key, BytesSpan plaintext)
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

auto aes_decrypt(AesContext& ctx, BytesSpan key, BytesSpan ciphertext)
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
// --- AesContext 实现 ---

AesContext::AesContext()
    : ptr_(EVP_CIPHER_CTX_new())
{
}

AesContext::~AesContext()
{
    if (ptr_ != nullptr)
        EVP_CIPHER_CTX_free(ptr_);
}

AesContext::AesContext(AesContext&& other) noexcept
    : ptr_(other.ptr_)
{
    other.ptr_ = nullptr;
}

AesContext& AesContext::operator=(AesContext&& other) noexcept
{
    if (this != &other) {
        if (ptr_ != nullptr)
            EVP_CIPHER_CTX_free(ptr_);
        ptr_ = other.ptr_;
        other.ptr_ = nullptr;
    }
    return *this;
}

}  // namespace Honey::Crypto::Utils
