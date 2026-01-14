#pragma once
#include "Fr.hpp"
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <stdexcept>

namespace CryptoUtils {
    using blst::byte;
  // SHA256
  inline std::vector<byte> sha256(const std::vector<byte> &data) {
    std::vector<byte> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
  }

  // XOR
  inline std::vector<byte> xor_bytes(const std::vector<byte>& a,
      const std::vector<byte>& b)
  {
      if (a.size() != b.size())
          throw std::runtime_error("XOR length mismatch");
      std::vector<byte> res(a.size());
      for (size_t i = 0; i < a.size(); ++i)
          res[i] = a[i] ^ b[i];
      return res;
  }

  // G1 Serialize
  inline std::vector<byte> serialize_g1(const blst::P1& p)
  {
      byte buf[48];
      p.compress(buf);
      return std::vector<byte>(buf, buf + 48);
  }

  // HashG: G1 -> 32 bytes
  inline std::vector<byte> hashG(const blst::P1& point)
  {
      return sha256(serialize_g1(point));
  }

  // HashH: (G1, 32-byte-V) -> G2
  inline blst::P2 hashH(const blst::P1& u, const std::vector<byte>& v)
  {
      std::vector<byte> u_bytes = serialize_g1(u);
      std::vector<byte> msg;
      msg.insert(msg.end(), u_bytes.begin(), u_bytes.end());
      msg.insert(msg.end(), v.begin(), v.end());

      const std::string DST = "TPKE_HASH_H_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
      blst::P2 h;
      h.hash_to(msg.data(), msg.size(), DST);
      return h;
  }

  // AES-256-CBC Encrypt
  inline std::vector<byte> aes_encrypt(const std::vector<byte>& key,
      const std::vector<byte>& plaintext)
  {
      EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
      std::vector<byte> iv(16);
      RAND_bytes(iv.data(), 16);

      std::vector<byte> ciphertext(plaintext.size() + 32);
      int len, ciphertext_len;

      EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());
      EVP_EncryptUpdate(ctx, ciphertext.data() + 16, &len, plaintext.data(),
          plaintext.size());
      ciphertext_len = len;
      EVP_EncryptFinal_ex(ctx, ciphertext.data() + 16 + len, &len);
      ciphertext_len += len;

      std::copy(iv.begin(), iv.end(), ciphertext.begin());
      ciphertext.resize(16 + ciphertext_len);

      EVP_CIPHER_CTX_free(ctx);
      return ciphertext;
  }

  // AES-256-CBC Decrypt
  inline std::vector<byte> aes_decrypt(const std::vector<byte>& key,
      const std::vector<byte>& ciphertext)
  {
      if (ciphertext.size() < 16)
          throw std::runtime_error("Ciphertext too short");

      EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
      std::vector<byte> iv(ciphertext.begin(), ciphertext.begin() + 16);
      std::vector<byte> plaintext(ciphertext.size());
      int len, plaintext_len;

      EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key.data(), iv.data());
      EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data() + 16,
          ciphertext.size() - 16);
      plaintext_len = len;

      if (1 != EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len)) {
          EVP_CIPHER_CTX_free(ctx);
          throw std::runtime_error("AES Decrypt Final failed");
      }
      plaintext_len += len;
      plaintext.resize(plaintext_len);

      EVP_CIPHER_CTX_free(ctx);
      return plaintext;
  }
}