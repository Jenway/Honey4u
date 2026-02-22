#pragma once

#include "isal_fwd.hpp"
#include "struct.hpp"
#include <expected>
#include <memory>
#include <span>
#include <system_error>

namespace Honey::Crypto::Merkle {

struct IsalMemoryArenaDeleter {
    void operator()(isal_memory_arena* arena) const noexcept;
};

struct IsalRsContextDeleter {
    void operator()(isal_rs_context* ctx) const noexcept;
};

struct RsContext {
    int K {};
    int N {};
    std::unique_ptr<isal_rs_context, IsalRsContextDeleter> c_context;
    std::unique_ptr<isal_memory_arena, IsalMemoryArenaDeleter> memory_arena;

    RsContext() noexcept = default;
    ~RsContext();
    RsContext(RsContext&&) noexcept = default;
    RsContext& operator=(RsContext&&) noexcept = default;
    RsContext(const RsContext&) = delete;
    RsContext& operator=(const RsContext&) = delete;

    [[nodiscard]] const unsigned char* encode_matrix_data() const;
    [[nodiscard]] const unsigned char* encode_g_tbls_data() const;

    static std::expected<RsContext, std::error_code> create(int K, int N);

    void build_decode_matrix(std::span<const int> shard_indexes,
        std::span<unsigned char> out_matrix) const;
};

auto rs_encode(const RsContext& ctx, MessageBuffer& msg)
    -> std::expected<ShardBlock, std::error_code>;

auto rs_decode(const RsContext& ctx, std::span<const ShardView> shards)
    -> std::expected<MessageBuffer, std::error_code>;

} // namespace Honey::Crypto::Merkle
