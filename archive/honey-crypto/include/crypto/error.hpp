#pragma once
#include <cstdint>
#include <system_error>

namespace Honey::Crypto {
enum class Error : std::uint8_t {
    Success = 0,
    BlstError,
    OpenSSLError,
    InvalidShare,
    VerificationFailed,
    NotEnoughShares,
    SerializationError,
    InvalidCiphertext,
    InvalidKey,
    Unknown
};

class HoneyCryptoErrorCategory : public std::error_category {
public:
    [[nodiscard]] const char* name() const noexcept override
    {
        return "HoneyCrypto";
    }

    [[nodiscard]] std::string message(int ev) const override
    {
        switch (static_cast<Error>(ev)) {
        case Error::Success:
            return "Success";
        case Error::BlstError:
            return "Blst failure";
        case Error::OpenSSLError:
            return "OpenSSL failure";
        case Error::InvalidShare:
            return "Invalid share";
        case Error::VerificationFailed:
            return "Verification failed";
        case Error::NotEnoughShares:
            return "Not enough shares";
        case Error::SerializationError:
            return "Serialization error";
        case Error::InvalidCiphertext:
            return "Invalid ciphertext";
        case Error::InvalidKey:
            return "Invalid key";
        default:
            return "Unknown Honey::Crypto error";
        }
    }
};

inline const std::error_category& tbls_category()
{
    static HoneyCryptoErrorCategory instance;
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
