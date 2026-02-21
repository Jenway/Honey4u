#pragma once

#include "isal_rs_codec.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward-declare OpenSSL type to avoid pulling in the full header here */
struct evp_md_ctx_st;

/**
 * Merkle 哈希上下文 — 类比 isal_memory_arena，为固定大小的树预分配节点缓冲区。
 *
 * nodes 数组以 1-based 二叉树布局存储哈希值：
 *   nodes[1]        — 根节点
 *   nodes[P..2P-1]  — 叶节点（P = bit_ceil(N)）
 * 每个节点占 32 字节（SHA-256）。
 */
struct merkle_context {
    struct evp_md_ctx_st* md_ctx; /* 复用的 OpenSSL EVP 上下文 */
    unsigned char* nodes; /* (2 * P * 32) 字节，P = bit_ceil(N) */
    int N; /* 实际叶节点数（分片数） */
    int P; /* bit_ceil(N) */
};

/**
 * 创建 merkle_context，为 N 个叶节点预分配节点缓冲区。
 * 失败返回 NULL。
 */
struct merkle_context* merkle_context_create(int N);

/**
 * 释放 merkle_context 及其所有资源。
 */
void merkle_context_free(struct merkle_context* ctx);

/**
 * 填充 ctx->nodes 并将根哈希写入 root_out[32]。
 * @param ctx    已创建的 merkle_context（N 须与 shards->N 匹配）
 * @param shards 编码后的分片块
 * @param root_out 输出根哈希（32 字节）
 * @return 0 成功，-1 失败
 */
int merkle_build_nodes(
    struct merkle_context* ctx,
    const struct isal_shard_block* shards,
    unsigned char root_out[32]);

/**
 * 计算叶节点哈希：SHA-256(0x00 || data)
 * @return 0 成功，-1 失败
 */
int merkle_hash_leaf(
    struct evp_md_ctx_st* ctx,
    const unsigned char* data,
    size_t len,
    unsigned char out[32]);

/**
 * 计算内部节点哈希：SHA-256(0x01 || left[32] || right[32])
 * @return 0 成功，-1 失败
 */
int merkle_hash_internal(
    struct evp_md_ctx_st* ctx,
    const unsigned char left[32],
    const unsigned char right[32],
    unsigned char out[32]);

#ifdef __cplusplus
}
#endif
