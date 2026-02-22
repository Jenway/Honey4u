#pragma once
#include "isal_fwd.hpp"
#include <cstddef>
#include <memory>
#include <span>

namespace Honey::Crypto::Merkle {

// --- MessageBuffer ---

struct IsalMessageBufferDeleter {
    void operator()(isal_message_buffer* p) const noexcept;
};

struct MessageBuffer {
    std::unique_ptr<isal_message_buffer, IsalMessageBufferDeleter> c_buffer;

    MessageBuffer() noexcept = default;
    ~MessageBuffer();
    MessageBuffer(MessageBuffer&&) noexcept = default;
    MessageBuffer& operator=(MessageBuffer&&) noexcept = default;
    MessageBuffer(const MessageBuffer&) = delete;
    MessageBuffer& operator=(const MessageBuffer&) = delete;

    void assign(std::span<const std::byte> input);
    [[nodiscard]] std::span<const std::byte> payload() const;
    [[nodiscard]] std::span<const std::byte> storage() const;
};

// --- ShardBlock ---

struct IsalShardBlockDeleter {
    void operator()(isal_shard_block* p) const noexcept;
};

struct ShardBlock {
    std::unique_ptr<isal_shard_block, IsalShardBlockDeleter> c_block;
    size_t block_size = 0;
    int K = 0;
    int N = 0;

    ShardBlock() noexcept = default;
    ~ShardBlock();
    ShardBlock(ShardBlock&&) noexcept = default;
    ShardBlock& operator=(ShardBlock&&) noexcept = default;
    ShardBlock(const ShardBlock&) = delete;
    ShardBlock& operator=(const ShardBlock&) = delete;

    static ShardBlock from_isal_shard_block(isal_shard_block* c_block);

    std::span<unsigned char> full_span();
    [[nodiscard]] std::span<const unsigned char> full_span() const;
    std::span<unsigned char> shard(int i);
    [[nodiscard]] std::span<const unsigned char> shard(int i) const;
};

using ShardView = isal_shard_view;

} // namespace Honey::Crypto::Merkle
