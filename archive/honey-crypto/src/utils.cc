#include "crypto/threshold/utils.hpp"
#include <algorithm> 
#include <blst.h> 
#include <openssl/evp.h> 
#include <openssl/rand.h> 
#include <openssl/sha.h> 
#include <openssl/types.h> 
#include <span> 
#include <cstddef> 
#include <stdexcept> 
#include <string>

namespace Honey::Crypto::Utils {

Hash256 sha256(BytesSpan data)
{
    Hash256 hash;
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

G1Serialized serialize_g1(const P1& p)
{
    G1Serialized buf;
    blst_p1_compress(buf.data(), p);
    return buf;
}

Hash256 hashG(const P1& point)
{
    return sha256(serialize_g1(point));
}

// HashH: (G1, V) -> G2.
P2 hashH(const P1& u, BytesSpan v)
{
    G1Serialized u_bytes = serialize_g1(u);

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

// AES-256-CBC Encrypt: Takes flexible spans as input.
std::vector<Byte> aes_encrypt(BytesSpan key, BytesSpan plaintext)
{
    if (key.size() != 32) {
        throw std::invalid_argument("AES key must be 32 bytes");
    }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    // Use std::vector for IV because it needs to be part of the dynamic output
    std::vector<Byte> iv(16);
    RAND_bytes(iv.data(), iv.size());

    std::vector<Byte> ciphertext(16 + plaintext.size() + 16); // IV + data + padding
    int len = 0;
    int ciphertext_len = 0;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data() + 16, &len, plaintext.data(), plaintext.size());
    ciphertext_len += len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + 16 + len, &len);
    ciphertext_len += len;

    // Prepend the IV to the ciphertext
    std::ranges::copy(iv, ciphertext.begin());
    ciphertext.resize(16 + ciphertext_len);

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

// AES-256-CBC Decrypt: Takes flexible spans as input.
// Consider returning std::expected for better error handling on decrypt failure.
std::vector<Byte> aes_decrypt(BytesSpan key, BytesSpan ciphertext)
{
    if (key.size() != 32) {
        throw std::invalid_argument("AES key must be 32 bytes");
    }
    if (ciphertext.size() < 16) {
        throw std::runtime_error("Ciphertext too short to contain IV");
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    BytesSpan iv(ciphertext.data(), 16);
    BytesSpan encrypted_data(ciphertext.data() + 16, ciphertext.size() - 16);

    std::vector<Byte> plaintext(encrypted_data.size());
    int len = 0;
    int plaintext_len = 0;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, encrypted_data.data(), encrypted_data.size());
    plaintext_len += len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("AES Decrypt Final failed (padding or key error)");
    }
    plaintext_len += len;
    plaintext.resize(plaintext_len);

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}
}
