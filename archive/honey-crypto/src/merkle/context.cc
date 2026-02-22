#include "crypto/merkle/ec_code.hpp"
#include "merkle/isal/isal_memory_arena.h"

// Declare isal_rs_context functions WITHOUT including isal_wrapper.h,
// which contains isal_decode_tables (C99 flexible array, C-only).
extern "C" {
struct isal_rs_context* isal_rs_context_create(int K, int N);
void isal_rs_context_free(struct isal_rs_context* ctx);
const unsigned char*
isal_rs_context_encode_matrix(const struct isal_rs_context* ctx);
const unsigned char*
isal_rs_context_encode_g_tbls(const struct isal_rs_context* ctx);
}
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

    RsContext result;
    result.K = K;
    result.N = N;
    result.c_context = std::unique_ptr<isal_rs_context, IsalRsContextDeleter>(c_ctx);
    result.memory_arena = std::unique_ptr<isal_memory_arena, IsalMemoryArenaDeleter>(arena);
    return result;
}

void RsContext::build_decode_matrix(std::span<const int> shard_indexes,
    std::span<unsigned char> out_matrix) const
{
    assert(shard_indexes.size() <= static_cast<size_t>(K));
    assert(out_matrix.size_bytes() >= shard_indexes.size() * static_cast<size_t>(K));
    const unsigned char* matrix = isal_rs_context_encode_matrix(c_context.get());
    assert(c_context && matrix);
    for (int i = 0; i < static_cast<int>(shard_indexes.size()); i++) {
        const int src_idx = shard_indexes[i];
        std::memcpy(&out_matrix[static_cast<size_t>(i) * K],
            &matrix[static_cast<size_t>(src_idx) * K],
            static_cast<size_t>(K));
    }
}

RsContext::~RsContext() = default;

const unsigned char* RsContext::encode_matrix_data() const
{
    return c_context ? isal_rs_context_encode_matrix(c_context.get()) : nullptr;
}

const unsigned char* RsContext::encode_g_tbls_data() const
{
    return c_context ? isal_rs_context_encode_g_tbls(c_context.get()) : nullptr;
}

void IsalMemoryArenaDeleter::operator()(
    isal_memory_arena* arena) const noexcept
{
    if (arena != nullptr) {
        isal_memory_arena_free(arena);
    }
}

void IsalRsContextDeleter::operator()(isal_rs_context* ctx) const noexcept
{
    if (ctx != nullptr) {
        isal_rs_context_free(ctx);
    }
}

}; // namespace Honey::Crypto::Merkle
