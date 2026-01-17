#include <cstdint>
#include <system_error>

namespace Honey::Crypto {
enum class Error : std::uint8_t {
    Success = 0,
    InvalidThreshold, // K 值不合法
    InvalidPlayerCount, // N 值不合法
    InvalidShareID, // ID 超出范围或不合法
    ShareVerificationFailed, // 份额验证失败
    SignatureVerificationFailed, // 主签名验证失败
    NotEnoughShares, // 聚合时份额数量不足
    MismatchedIdsAndSigs, // ID 列表和签名列表长度不一致
    OpenSSLError, // 随机数生成失败
    DuplicatePlayerID
};

class TBLSErrorCategory : public std::error_category {
public:
    [[nodiscard]] const char* name() const noexcept override { return "HoneyCrypto"; }

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
} // namespace Honey::Crypto

namespace std {
template <>
struct is_error_code_enum<Honey::Crypto::Error> : true_type { };
} // namespace std
