#include <algorithm>
#include <cstring>
#include <expected>
#include <iostream>
#include <random>
#include <ranges>
#include <set>
#include <stdexcept>
#include <string>
#include <system_error>
#include <vector>

#include "Fr.hpp"

namespace TBLS {
using blst::byte;

struct PrivateKeyShare {
    int id;
    Fr sk;
    blst::P2 vk; // Master Public Key
    std::vector<blst::P2> vks; // Verification Vector
};

struct PublicKey {
    int l, k;
    blst::P2 vk;
    std::vector<blst::P2> vks;
};

struct DealerResult {
    PublicKey pk;
    std::vector<PrivateKeyShare> sks;
};

[[nodiscard]]
auto dealer(int players, int k) -> std::expected<DealerResult, std::error_code>;
;

blst::P1 sign_share(const PrivateKeyShare& sk_share, const std::string& msg);

[[nodiscard]]
auto verify_share(const PublicKey& pk, int id, std::string_view msg, const blst::P1& sig)
    -> std::expected<void, std::error_code>;

[[nodiscard]]
auto combine_shares(const PublicKey& pk, std::span<const int> ids, std::span<const blst::P1> sigs) -> std::expected<blst::P1, std::error_code>;

// 验证主签名
[[nodiscard]]
auto verify_signature(const PublicKey& pk, std::string_view msg, const blst::P1& sig)
    -> std::expected<void, std::error_code>;
}

namespace TBLS {

// 1. 定义错误枚举
enum class Error {
    Success = 0,
    InvalidThreshold, // K 值不合法
    InvalidPlayerCount, // N 值不合法
    InvalidShareID, // ID 超出范围或不合法
    ShareVerificationFailed, // 份额验证失败
    SignatureVerificationFailed, // 主签名验证失败
    NotEnoughShares, // 聚合时份额数量不足
    MismatchedIdsAndSigs, // ID 列表和签名列表长度不一致
    OpenSSLError // 随机数生成失败
};

class TBLSErrorCategory : public std::error_category {
public:
    const char* name() const noexcept override { return "TBLS"; }

    std::string message(int ev) const override
    {
        switch (static_cast<Error>(ev)) {
        case Error::Success:
            return "Success";
        case Error::InvalidThreshold:
            return "Threshold k must be between 1 and players";
        case Error::InvalidPlayerCount:
            return "Player count must be positive";
        case Error::InvalidShareID:
            return "Share ID is out of valid range";
        case Error::ShareVerificationFailed:
            return "Share verification failed";
        case Error::SignatureVerificationFailed:
            return "Master signature verification failed";
        case Error::NotEnoughShares:
            return "Not enough shares to reconstruct signature";
        case Error::MismatchedIdsAndSigs:
            return "IDs and Signatures count mismatch";
        case Error::OpenSSLError:
            return "OpenSSL RNG failure";
        default:
            return "Unknown TBLS error";
        }
    }
};

inline const std::error_category& tbls_category()
{
    static TBLSErrorCategory instance;
    return instance;
}

inline std::error_code make_error_code(Error e)
{
    return { static_cast<int>(e), tbls_category() };
}

} // namespace TBLS

namespace std {
template <>
struct is_error_code_enum<TBLS::Error> : true_type { };
}