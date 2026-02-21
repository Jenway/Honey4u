#include "crypto/merkle/ec_code.hpp"
#include "crypto/merkle/isal/isal_rs_codec.h"
#include <cstddef>

namespace Honey::Crypto::Merkle {

auto rs_encode(
    const RsContext& ctx,
    MessageBuffer& msg)
    -> std::expected<ShardBlock, std::error_code>
{
    auto* c_block = isal_rs_encode_create(
        ctx.memory_arena.get(),
        ctx.encode_g_tbls_data(),
        msg.payload().data(),
        msg.payload_size);

    if (c_block == nullptr) {
        return std::unexpected(std::make_error_code(std::errc::operation_not_permitted));
    }

    return ShardBlock::from_isal_shard_block(c_block);
}

std::expected<void, std::error_code>
rs_decode_into(
    const RsContext& ctx,
    std::span<const ShardView> shards,
    MessageBuffer& out)
{
    auto* arena = ctx.memory_arena.get();

    const int fill = isal_memory_arena_fill_shards(
        arena, shards.data(), static_cast<int>(shards.size()));
    if (fill != 0) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    out.storage.resize(static_cast<size_t>(arena->K) * arena->block_size);

    size_t payload_size = 0;
    const int status = isal_rs_decode_into(
        arena, ctx.encode_matrix_data(), out.storage.data(), &payload_size);
    if (status != 0) {
        switch (status) {
        case -2:
            return std::unexpected(std::make_error_code(std::errc::operation_not_permitted));
        default:
            return std::unexpected(std::make_error_code(std::errc::invalid_argument));
        }
    }

    out.payload_size = payload_size;
    return {};
}

}; // namespace Honey::Crypto::Merkle
