#pragma once

#include <expected>
#include <map>
#include <system_error>
#include <vector>

#include "crypto/common.hpp"

namespace Honey::Crypto::ErasureCode {

class Context {
public:
    [[nodiscard]]
    static std::expected<Context, std::error_code> create(int K, int N);

    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;

    Context(Context&&) noexcept = default;
    Context& operator=(Context&&) noexcept = default;

    ~Context() = default;

    [[nodiscard]] int K() const noexcept { return K_; }
    [[nodiscard]] int N() const noexcept { return N_; }

private:
    int K_;
    int N_;
    std::vector<unsigned char> encode_matrix_;
    std::vector<unsigned char> parity_g_tbls_;
    std::vector<unsigned char> decode_g_tbls_;

    Context(int K, int N, std::vector<unsigned char>&& encode_matrix,
        std::vector<unsigned char>&& parity_g_tbls,
        std::vector<unsigned char>&& decode_g_tbls)
        : K_(K)
        , N_(N)
        , encode_matrix_(std::move(encode_matrix))
        , parity_g_tbls_(std::move(parity_g_tbls))
        , decode_g_tbls_(std::move(decode_g_tbls))
    {
    }

    friend class ErasureCodeImpl;
};

[[nodiscard]]
auto encode(const Context& ctx, BytesSpan data)
    -> std::expected<std::vector<std::vector<Byte>>, std::error_code>;

[[nodiscard]]
auto decode(const Context& ctx, const std::map<int, std::vector<Byte>>& received_shards)
    -> std::expected<std::vector<Byte>, std::error_code>;

} // namespace Honey::Crypto::ErasureCode
