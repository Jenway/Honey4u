#pragma once

#include "crypto/merkle/isal/isal_memory_arena.h"
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

/**
 * @param arena 内存 Arena
 * @param encode_tables 编码表（K*(N-K)*32 字节）
 * @param input_data 输入数据
 * @param input_len 输入数据长度
 * @return 分片块，失败返回 NULL
 */
struct isal_shard_block* isal_rs_encode_create(
    const struct isal_memory_arena* arena,
    const unsigned char* encode_tables,
    const void* input_data,
    size_t input_len);

/**
 * 释放分片块
 */
void isal_shard_block_free(struct isal_shard_block* block);

/**
 * 解码，直接写入调用方提供的缓冲区（零堆分配）
 * @param arena         内存 Arena，已由 isal_memory_arena_fill_shards 填充
 *                      （arena->block_size 由 fill_shards 写入）
 * @param encode_matrix 编码矩阵（N*K 字节）
 * @param output        输出缓冲区，调用方负责分配，大小须 >= K * arena->block_size
 * @param payload_size  [out] 实际 payload 字节数（不含 header / padding）
 * @return 0=成功, -1=参数错误, -2=矩阵不可逆
 */
int isal_rs_decode_into(
    const struct isal_memory_arena* arena,
    const unsigned char* encode_matrix,
    void* output,
    size_t* payload_size);

/**
 * 释放对齐内存
 */
void isal_aligned_free(void* ptr);

#ifdef __cplusplus
}
#endif
