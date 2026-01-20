#pragma once

#include "crypto/blst/P1.hpp"
#include "crypto/blst/P2.hpp"
#include "crypto/common.hpp"
#include <memory>
#include <openssl/evp.h>
#include <vector>

namespace Honey::Crypto::impl {

using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX,
    decltype([](EVP_MD_CTX* ctx) {
        EVP_MD_CTX_free(ctx);
    })>;

} // namespace Honey::Crypto::impl
namespace Honey::Crypto::Utils {

using P1 = bls::P1;
using P2 = bls::P2;

Hash256 hashG(const P1& point);

// HashH: (G1, V) -> G2.
P2 hashH(const P1& u, BytesSpan v);

// XOR: Inputs are now flexible spans. Output is still vector as size is dynamic.
std::vector<Byte> xor_bytes(BytesSpan a, BytesSpan b);

} // namespace Honey::Crypto::Utils
