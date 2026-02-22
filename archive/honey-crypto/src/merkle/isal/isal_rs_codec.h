#pragma once

#include "isal_memory_arena.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 分片块结构（编码结果）
 */
struct isal_shard_block {
    void* storage; /* 对齐的连续内存块 (N * block_size 字节) */
    size_t block_size; /* 每个分片的大小（已对齐到 32 字节） */
    int K; /* 数据分片数 */
    int N; /* 总分片数 */
};

struct isal_shard_block* isal_rs_encode_create(
    const struct isal_memory_arena* arena,
    const unsigned char* encode_tables,
    const void* input_data,
    size_t input_len);

void isal_shard_block_free(struct isal_shard_block* block);

int isal_rs_decode_into(
    const struct isal_memory_arena* arena,
    const unsigned char* encode_matrix,
    void* output,
    size_t* payload_size);

struct isal_message_buffer* isal_rs_decode_create(
    const struct isal_memory_arena* arena,
    const unsigned char* encode_matrix);

void isal_aligned_free(void* ptr);

#ifdef __cplusplus
}
#endif
