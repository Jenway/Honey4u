#include <cstdint>
#include <system_error>

namespace Honey::Crypto {
enum class Error : std::uint8_t {
    Success = 0,
    BlstError,
    OpenSSLError,
};

class HoneyCryptoErrorCategory : public std::error_category {
public:
    [[nodiscard]] const char* name() const noexcept override { return "HoneyCrypto"; }

    [[nodiscard]] std::string message(int ev) const override
    {
        switch (static_cast<Error>(ev)) {
        case Error::Success:
            return "Success";
        case Error::BlstError:
            return "Blst failure";
        case Error::OpenSSLError:
            return "OpenSSL failure";
        default:
            return "Unknown Hoeny::Crypto error";
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
