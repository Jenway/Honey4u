#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * RS 内存 Arena（复用临时缓冲区）
 * 用于避免在每次编码/解码时重复分配临时缓冲区
 * 因为 K 和 N 在运行期间不变，所以可以创建一个 arena 并复用
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

/**
 * 分片视图
 */
struct isal_shard_view {
    int index;
    const unsigned char* data;
    size_t block_size;
};

/**
 * 创建内存 Arena（基于 K, N 参数预分配临时缓冲区）
 * @param K 数据分片数
 * @param N 总分片数
 * @return Arena 指针，失败返回 NULL
 *
 * 调用者必须使用 isal_memory_arena_free 释放
 */
struct isal_memory_arena* isal_memory_arena_create(int K, int N);

/**
 * 释放内存 Arena
 */
void isal_memory_arena_free(struct isal_memory_arena* arena);

/**
 * 将分片索引和数据指针写入 arena 缓冲区
 * @param arena 内存 Arena
 * @param shards 分片视图数组
 * @param count 传入的分片数，须等于 arena->K
 * @return 0 成功，-1 参数错误（含 count != K），-2 分片 block_size 不一致
 */
int isal_memory_arena_fill_shards(
    struct isal_memory_arena* arena,
    const struct isal_shard_view* shards,
    int count);

#ifdef __cplusplus
}
#endif
