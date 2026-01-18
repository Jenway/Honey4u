#pragma once

#include <array>
#include <expected>
#include <system_error>

#include "common.hpp"

struct secp256k1_context_struct;

namespace Honey::Crypto::Ecdsa {

constexpr auto PRIV_KEY_SIZE = 32;
constexpr auto PUB_KEY_SIZE = 33; // 压缩公钥必须是 33
constexpr auto SIG_SIZE = 64; // 紧凑签名必须是 64

using PrivateKey = std::array<Byte, PRIV_KEY_SIZE>;
using PublicKey = std::array<Byte, PUB_KEY_SIZE>;
using Signature = std::array<Byte, SIG_SIZE>;

class Context {
public:
    Context();
    ~Context();

    Context(Context&& other) noexcept;
    Context& operator=(Context&& other) noexcept;
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    [[nodiscard]] const secp256k1_context_struct* get() const { return ptr_; }

private:
    secp256k1_context_struct* ptr_ = nullptr;
};

auto sign(const Context& ctx,
    const PrivateKey& priv_key,
    BytesSpan msg)
    -> std::expected<Signature, std::error_code>;

bool verify(const Context& ctx,
    const PublicKey& pub_key,
    BytesSpan msg,
    const Signature& sig);

auto get_public_key(const Context& ctx,
    const PrivateKey& priv_key)
    -> std::expected<PublicKey, std::error_code>;

} // namespace Honey::Crypto::Ecdsa
