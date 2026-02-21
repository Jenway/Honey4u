#pragma once
#include "crypto/merkle/isal/isal_rs_codec.h"
#include <cstddef>
#include <memory>
#include <span>
#include <vector>

namespace Honey::Crypto::Merkle {

extern "C" {
void* isal_pack_message(const void* data, size_t len, size_t* out_size);
const void* isal_unpack_message(const void* packed_data, size_t packed_size, size_t* out_payload_size);
}

struct IsalShardBlockDeleter {
    void operator()(isal_shard_block* p) const noexcept
    {
        if (p != nullptr) {
            isal_shard_block_free(p);
        }
    }
};

struct MessageBuffer {
    std::vector<std::byte> storage;
    size_t payload_size = 0;

    void assign(std::span<const std::byte> input)
    {
        payload_size = input.size();
        size_t total_size = 0;
        void* packed = isal_pack_message(input.data(), input.size(), &total_size);

        if (packed != nullptr) {
            storage.resize(total_size);
            std::memcpy(storage.data(), packed, total_size);
            free(packed);
        } else {
            storage.clear();
            payload_size = 0;
        }
    }

    [[nodiscard]] std::span<const std::byte> payload() const
    {
        if (storage.size() < 4)
            return {};

        size_t size = 0;
        const void* ptr = isal_unpack_message(storage.data(), storage.size(), &size);
        if (ptr != nullptr && size == payload_size) {
            return std::span<const std::byte> {
                static_cast<const std::byte*>(ptr), size
            };
        }
        return {};
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
