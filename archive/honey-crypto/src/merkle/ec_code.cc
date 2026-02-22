#include "crypto/merkle/ec_code.hpp"
#include "crypto/merkle/isal/isal_rs_codec.h"
#include <cstddef>

namespace Honey::Crypto::Merkle {

auto rs_encode(
    const RsContext& ctx,
    MessageBuffer& msg)
    -> std::expected<ShardBlock, std::error_code>
{
    if (!msg.c_buffer) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    auto payload = msg.payload();
    auto* c_block = isal_rs_encode_create(
        ctx.memory_arena.get(),
        ctx.encode_g_tbls_data(),
        payload.data(),
        payload.size());

    if (c_block == nullptr) {
        return std::unexpected(std::make_error_code(std::errc::operation_not_permitted));
    }

    return ShardBlock::from_isal_shard_block(c_block);
}

std::expected<MessageBuffer, std::error_code>
rs_decode(
    const RsContext& ctx,
    std::span<const ShardView> shards)
{
    auto* arena = ctx.memory_arena.get();

    const int fill = isal_memory_arena_fill_shards(
        arena, shards.data(), static_cast<int>(shards.size()));
    if (fill != 0) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    // 直接解码到 isal_message_buffer（零拷贝）
    auto* c_buffer = isal_rs_decode_create(arena, ctx.encode_matrix_data());
    if (c_buffer == nullptr) {
        return std::unexpected(std::make_error_code(std::errc::operation_not_permitted));
    }

    // 包装为 C++ MessageBuffer
    MessageBuffer result;
    result.c_buffer.reset(c_buffer);

    return result;
}

}; // namespace Honey::Crypto::Merkle
