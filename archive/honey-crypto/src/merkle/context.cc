#include "crypto/merkle/ec_code.hpp"
#include "crypto/merkle/isal/isal_memory_arena.h"
#include "crypto/merkle/isal/isal_wrapper.h"
#include <cassert>
#include <cstring>

namespace Honey::Crypto::Merkle {

std::expected<RsContext, std::error_code> RsContext::create(int K, int N)
{
    if (K <= 0 || N <= K) {
        return std::unexpected(std::make_error_code(std::errc::invalid_argument));
    }

    auto* c_ctx = isal_rs_context_create(K, N);
    if (c_ctx == nullptr) {
        return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
    }

    auto* arena = isal_memory_arena_create(K, N);
    if (arena == nullptr) {
        isal_rs_context_free(c_ctx);
        return std::unexpected(std::make_error_code(std::errc::not_enough_memory));
    }

    return RsContext {
        .K = K,
        .N = N,
        .c_context = std::unique_ptr<isal_rs_context, IsalRsContextDeleter>(c_ctx),
        .memory_arena = std::unique_ptr<isal_memory_arena, IsalMemoryArenaDeleter>(arena)
    };
}

void RsContext::build_decode_matrix(
    std::span<const int> shard_indexes,
    std::span<unsigned char> out_matrix) const
{
    assert(shard_indexes.size() <= static_cast<size_t>(K));
    assert(out_matrix.size_bytes() >= shard_indexes.size() * static_cast<size_t>(K));
    assert(c_context && c_context->encode_matrix);

    const unsigned char* matrix = c_context->encode_matrix;
    for (int i = 0; i < static_cast<int>(shard_indexes.size()); i++) {
        const int src_idx = shard_indexes[i];
        std::memcpy(&out_matrix[static_cast<size_t>(i) * K], &matrix[static_cast<size_t>(src_idx) * K], static_cast<size_t>(K));
    }
}

}; // namespace Honey::Crypto::Merkle
