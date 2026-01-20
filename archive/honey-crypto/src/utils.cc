#include "threshold/utils.hpp"
#include "crypto/common.hpp"
#include <cstddef>
#include <cstring>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <string>

namespace Honey::Crypto::Utils {

Hash256 sha256(BytesSpan data)
{
    Hash256 hash;
    size_t len = 0;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    EVP_Q_digest(
        nullptr, "SHA256", nullptr,
        u8ptr(data), data.size(),
        u8ptr(hash.data()), &len);
#else
    // 兼容旧版本或通用写法
    EvpMdCtxPtr ctx(EVP_MD_CTX_new());
    EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx.get(), u8ptr(data), data.size());
    EVP_DigestFinal_ex(ctx.get(), u8ptr(hash.data()), &len);
#endif

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

} // namespace Honey::Crypto::Utils
