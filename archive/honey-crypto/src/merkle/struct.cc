#include "crypto/merkle/struct.hpp"

// isal_rs_codec.h is safe to include from C++ — isal_shard_block has no flexible array.
#include "merkle/isal/isal_rs_codec.h"

// Declare isal_message_buffer functions WITHOUT including the struct definition,
// which contains a C99 flexible array and must not be included from C++.
extern "C" {
struct isal_message_buffer* isal_message_buffer_create(const void* data, size_t len);
const void* isal_message_buffer_payload(const struct isal_message_buffer* msg);
const void* isal_message_buffer_storage(const struct isal_message_buffer* msg);
size_t isal_message_buffer_storage_size(const struct isal_message_buffer* msg);
size_t isal_message_buffer_payload_size(const struct isal_message_buffer* msg);
void isal_message_buffer_free(struct isal_message_buffer* msg);
}

namespace Honey::Crypto::Merkle {

// --- IsalMessageBufferDeleter ---

void IsalMessageBufferDeleter::operator()(isal_message_buffer* p) const noexcept
{
    if (p != nullptr) {
        isal_message_buffer_free(p);
    }
}

// --- MessageBuffer ---

MessageBuffer::~MessageBuffer() = default;

void MessageBuffer::assign(std::span<const std::byte> input)
{
    auto* buffer = isal_message_buffer_create(input.data(), input.size());
    c_buffer.reset(buffer);
}

std::span<const std::byte> MessageBuffer::payload() const
{
    if (!c_buffer) {
        return {};
    }
    const void* ptr = isal_message_buffer_payload(c_buffer.get());
    if (!ptr) {
        return {};
    }
    return { static_cast<const std::byte*>(ptr), isal_message_buffer_payload_size(c_buffer.get()) };
}

std::span<const std::byte> MessageBuffer::storage() const
{
    if (!c_buffer) {
        return {};
    }
    const void* ptr = isal_message_buffer_storage(c_buffer.get());
    const size_t size = isal_message_buffer_storage_size(c_buffer.get());
    if (!ptr || size == 0) {
        return {};
    }
    return { static_cast<const std::byte*>(ptr), size };
}

// --- IsalShardBlockDeleter ---

void IsalShardBlockDeleter::operator()(isal_shard_block* p) const noexcept
{
    if (p != nullptr) {
        isal_shard_block_free(p);
    }
}

// --- ShardBlock ---

ShardBlock::~ShardBlock() = default;

ShardBlock ShardBlock::from_isal_shard_block(isal_shard_block* c_blk)
{
    ShardBlock block;
    if (c_blk == nullptr) {
        return block;
    }
    block.c_block.reset(c_blk);
    block.block_size = c_blk->block_size;
    block.K = c_blk->K;
    block.N = c_blk->N;
    return block;
}

std::span<unsigned char> ShardBlock::full_span()
{
    if (!c_block || c_block->storage == nullptr) {
        return {};
    }
    return { static_cast<unsigned char*>(c_block->storage), static_cast<size_t>(N) * block_size };
}

std::span<const unsigned char> ShardBlock::full_span() const
{
    if (!c_block || c_block->storage == nullptr) {
        return {};
    }
    return { static_cast<const unsigned char*>(c_block->storage), static_cast<size_t>(N) * block_size };
}

std::span<unsigned char> ShardBlock::shard(int i)
{
    return full_span().subspan(static_cast<size_t>(i) * block_size, block_size);
}

std::span<const unsigned char> ShardBlock::shard(int i) const
{
    return full_span().subspan(static_cast<size_t>(i) * block_size, block_size);
}

} // namespace Honey::Crypto::Merkle
