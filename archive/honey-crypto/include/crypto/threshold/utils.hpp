#pragma once

#include <array>
#include <span>
#include <vector>

#include "crypto/blst/blst_wrapper.hpp"
#include "crypto/common.hpp"


namespace Honey::Crypto::Utils {

using P1 = bls::P1;
using P2 = bls::P2;

using Hash256 = std::array<Byte, 32>;
using G1Serialized = std::array<Byte, 48>;
using AesKey = std::array<Byte, 32>; // AES-256 key

Hash256 sha256(BytesSpan data);

G1Serialized serialize_g1(const P1& p);

Hash256 hashG(const P1& point);

// HashH: (G1, V) -> G2. 
P2 hashH(const P1& u, BytesSpan v);

// XOR: Inputs are now flexible spans. Output is still vector as size is dynamic.
std::vector<Byte> xor_bytes(BytesSpan a, BytesSpan b);

// AES-256-CBC Encrypt: Takes flexible spans as input.
std::vector<Byte> aes_encrypt(BytesSpan key, BytesSpan plaintext);

// AES-256-CBC Decrypt: Takes flexible spans as input.
// Consider returning std::expected for better error handling on decrypt failure.
std::vector<Byte> aes_decrypt(BytesSpan key, BytesSpan ciphertext);

} // namespace Honey::Crypto::Utils