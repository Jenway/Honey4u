#pragma once

#include "isal_rs_codec.h"
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Forward-declare OpenSSL type to avoid pulling in the full header here */
struct evp_md_ctx_st;

/**
 * Merkle 哈希上下文 — 为固定大小的树预分配节点缓冲区。
 *
 * nodes 数组以 1-based 二叉树布局存储哈希值：
 *   nodes[1]        — 根节点
 *   nodes[P..2P-1]  — 叶节点（P = bit_ceil(N)）
 * 每个节点占 32 字节（SHA-256）。
 */
struct merkle_context {
    struct evp_md_ctx_st* md_ctx; /* 复用的 OpenSSL EVP 上下文 */
    unsigned char* nodes; /* (2 * P * 32) 字节，P = bit_ceil(N) */
    int N; /* 实际叶节点数 */
    int P; /* bit_ceil(N) */
};

struct merkle_context* merkle_context_create(int N);
void merkle_context_free(struct merkle_context* ctx);

int merkle_build_nodes(
    struct merkle_context* ctx,
    const struct isal_shard_block* shards,
    unsigned char root_out[32]);

int merkle_hash_leaf(
    struct evp_md_ctx_st* ctx,
    const unsigned char* data,
    size_t len,
    unsigned char out[32]);

int merkle_hash_internal(
    struct evp_md_ctx_st* ctx,
    const unsigned char left[32],
    const unsigned char right[32],
    unsigned char out[32]);

#ifdef __cplusplus
}
#endif
