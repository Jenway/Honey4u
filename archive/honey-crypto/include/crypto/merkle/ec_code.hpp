#pragma once

extern "C" {
#include "crypto/merkle/isal/isal_memory_arena.h"
#include "crypto/merkle/isal/isal_wrapper.h"
}

#include "struct.hpp"
#include <array>
#include <cstddef>
#include <expected>
#include <memory>
#include <span>
#include <system_error>

namespace Honey::Crypto::Merkle {

constexpr size_t SHA256_BYTES = 32;
using Hash = std::array<std::byte, SHA256_BYTES>;

struct IsalMemoryArenaDeleter {
    void operator()(isal_memory_arena* arena) const
    {
        if (arena != nullptr)
            isal_memory_arena_free(arena);
    }
};

struct IsalRsContextDeleter {
    void operator()(isal_rs_context* ctx) const
    {
        if (ctx != nullptr)
            isal_rs_context_free(ctx);
    }
};

struct RsContext {
    int K;
    int N;
    std::unique_ptr<isal_rs_context, IsalRsContextDeleter> c_context;
    std::unique_ptr<isal_memory_arena, IsalMemoryArenaDeleter> memory_arena;

    [[nodiscard]] const unsigned char* encode_matrix_data() const
    {
        return c_context ? c_context->encode_matrix : nullptr;
    }

    [[nodiscard]] const unsigned char* encode_g_tbls_data() const
    {
        return c_context ? c_context->encode_g_tbls : nullptr;
    }

    static std::expected<RsContext, std::error_code> create(int K, int N);

    void build_decode_matrix(
        std::span<const int> shard_indexes,
        std::span<unsigned char> out_matrix) const;
};

auto rs_encode(
    const RsContext& ctx,
    MessageBuffer& msg)
    -> std::expected<ShardBlock, std::error_code>;

auto rs_decode(
    const RsContext& ctx,
    std::span<const ShardView> shards)
    -> std::expected<MessageBuffer, std::error_code>;

} // namespace Honey::Crypto::Merkle
