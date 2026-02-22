#pragma once

// isal_shard_view is defined in the public header.
// Include it here so C code in this module can use the type.
#include "crypto/merkle/isal_fwd.hpp"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * RS 内存 Arena（复用临时缓冲区）
 */
struct isal_memory_arena {
    int K;
    int N;
    /* 编码用临时缓冲区 */
    unsigned char** encode_ptrs; /* N 个指针数组 */

    /* 解码用临时缓冲区 */
    unsigned char* decode_matrix; /* K*K 字节 */
    unsigned char* decode_invert_matrix; /* K*K 字节 */
    unsigned char** decode_input_ptrs; /* K 个指针数组 */
    unsigned char** decode_output_ptrs; /* K 个指针数组 */

    /* 解码索引和分片指针缓冲区 */
    int* shard_indexes; /* K 个索引 */
    const void** shard_ptrs; /* K 个分片指针 */

    /* 由 isal_memory_arena_fill_shards 填充，供解码使用 */
    size_t block_size; /* 所有分片的统一大小（字节） */
};

struct isal_memory_arena* isal_memory_arena_create(int K, int N);
void isal_memory_arena_free(struct isal_memory_arena* arena);

int isal_memory_arena_fill_shards(struct isal_memory_arena* arena,
    const struct isal_shard_view* shards,
    int count);

#ifdef __cplusplus
}
#endif
