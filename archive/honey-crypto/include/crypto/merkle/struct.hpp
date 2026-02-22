#pragma once
#include "crypto/merkle/isal/isal_message.h"
#include "crypto/merkle/isal/isal_rs_codec.h"
#include <cstddef>
#include <memory>
#include <span>

namespace Honey::Crypto::Merkle {

struct IsalMessageBufferDeleter {
    void operator()(isal_message_buffer* p) const noexcept
    {
        if (p != nullptr) {
            isal_message_buffer_free(p);
        }
    }
};

struct MessageBuffer {
    std::unique_ptr<isal_message_buffer, IsalMessageBufferDeleter> c_buffer;

    void assign(std::span<const std::byte> input)
    {
        auto* buffer = isal_message_buffer_create(input.data(), input.size());
        c_buffer.reset(buffer);
    }

    [[nodiscard]] std::span<const std::byte> payload() const
    {
        if (!c_buffer) {
            return {};
        }

        const void* ptr = isal_message_buffer_payload(c_buffer.get());
        if (!ptr) {
            return {};
        }

        return std::span<const std::byte> {
            static_cast<const std::byte*>(ptr),
            c_buffer->payload_size
        };
    }

    [[nodiscard]] std::span<const std::byte> storage() const
    {
        if (!c_buffer) {
            return {};
        }

        const void* ptr = isal_message_buffer_storage(c_buffer.get());
        size_t size = isal_message_buffer_storage_size(c_buffer.get());

        if (!ptr || size == 0) {
            return {};
        }

        return std::span<const std::byte> {
            static_cast<const std::byte*>(ptr),
            size
        };
    }
};

struct IsalShardBlockDeleter {
    void operator()(isal_shard_block* p) const noexcept
    {
        if (p != nullptr) {
            isal_shard_block_free(p);
        }
    }
};

struct ShardBlock {
    std::unique_ptr<isal_shard_block, IsalShardBlockDeleter> c_block;
    size_t block_size = 0;
    int K = 0;
    int N = 0;

    static ShardBlock from_isal_shard_block(isal_shard_block* c_block)
    {
        ShardBlock block;
        if (c_block == nullptr) {
            return block;
        }

        block.c_block.reset(c_block);
        block.block_size = c_block->block_size;
        block.K = c_block->K;
        block.N = c_block->N;

        return block;
    }

    // 预先封装一个总体的 span
    std::span<unsigned char> full_span()
    {
        if (!c_block || (c_block->storage == nullptr)) {
            return {};
        }
        return { static_cast<unsigned char*>(c_block->storage), static_cast<size_t>(N) * block_size };
    }

    std::span<const unsigned char> full_span() const
    {
        if (!c_block || (c_block->storage == nullptr)) {
            return {};
        }
        return { static_cast<const unsigned char*>(c_block->storage), static_cast<size_t>(N) * block_size };
    }

    std::span<unsigned char> shard(int i)
    {
        return full_span().subspan(i * block_size, block_size);
    }

    [[nodiscard]] std::span<const unsigned char> shard(int i) const
    {
        return full_span().subspan(i * block_size, block_size);
    }
};

using ShardView = isal_shard_view;

} // namespace Honey::Crypto::Merkle
