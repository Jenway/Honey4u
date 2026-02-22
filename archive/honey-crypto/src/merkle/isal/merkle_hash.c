#include "merkle_hash.h"
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
   内部辅助
   ============================================================================
 */

static const unsigned char LEAF_PREFIX = 0x00;
static const unsigned char INTERNAL_PREFIX = 0x01;

/* 计算大于等于 n 的最小 2 的幂（n >= 1） */
static int next_power_of_two(int n)
{
    if (n <= 1)
        return 1;
    int p = 1;
    while (p < n)
        p <<= 1;
    return p;
}

/* ============================================================================
   生命周期
   ============================================================================
 */

struct merkle_context* merkle_context_create(int N)
{
    if (N <= 0)
        return NULL;

    struct merkle_context* ctx = (struct merkle_context*)calloc(1, sizeof(struct merkle_context));
    if (!ctx)
        return NULL;

    ctx->md_ctx = EVP_MD_CTX_new();
    if (!ctx->md_ctx)
        goto fail;

    int P = next_power_of_two(N);
    /* 索引 1..2P-1，共 2P 个槽，每槽 32 字节；索引 0 不使用 */
    ctx->nodes = (unsigned char*)calloc((size_t)(2 * P), 32);
    if (!ctx->nodes)
        goto fail;

    ctx->N = N;
    ctx->P = P;
    return ctx;

fail:
    merkle_context_free(ctx);
    return NULL;
}

void merkle_context_free(struct merkle_context* ctx)
{
    if (!ctx)
        return;
    if (ctx->md_ctx)
        EVP_MD_CTX_free(ctx->md_ctx);
    if (ctx->nodes)
        free(ctx->nodes);
    free(ctx);
}

/* ============================================================================
   哈希原语
   ============================================================================
 */

int merkle_hash_leaf(struct evp_md_ctx_st* ctx, const unsigned char* data,
    size_t len, unsigned char out[32])
{
    unsigned int out_len = 0;
    if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) || 1 != EVP_DigestUpdate(ctx, &LEAF_PREFIX, 1) || 1 != EVP_DigestUpdate(ctx, data, len) || 1 != EVP_DigestFinal_ex(ctx, out, &out_len))
        return -1;
    return 0;
}

int merkle_hash_internal(struct evp_md_ctx_st* ctx,
    const unsigned char left[32],
    const unsigned char right[32], unsigned char out[32])
{
    unsigned int out_len = 0;
    if (1 != EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) || 1 != EVP_DigestUpdate(ctx, &INTERNAL_PREFIX, 1) || 1 != EVP_DigestUpdate(ctx, left, 32) || 1 != EVP_DigestUpdate(ctx, right, 32) || 1 != EVP_DigestFinal_ex(ctx, out, &out_len))
        return -1;
    return 0;
}

/* ============================================================================
   节点构建
   ============================================================================
 */

int merkle_build_nodes(struct merkle_context* ctx,
    const struct isal_shard_block* shards,
    unsigned char root_out[32])
{
    if (!ctx || !shards || !root_out || shards->N != ctx->N)
        return -1;

    int N = ctx->N;
    int P = ctx->P;
    unsigned char* nodes = ctx->nodes; /* nodes[idx * 32] = hash at index idx */
    EVP_MD_CTX* md = ctx->md_ctx;

    /* 1. 真实叶节点哈希 */
    for (int i = 0; i < N; ++i) {
        const unsigned char* shard_data = (const unsigned char*)shards->storage + (size_t)i * shards->block_size;

        if (merkle_hash_leaf(md, shard_data, shards->block_size,
                nodes + (size_t)(P + i) * 32)
            != 0)
            return -1;
    }

    /* 2. 填充叶节点（N 不是 2 的幂时） */
    if (N < P) {
        unsigned char pad_hash[32];
        if (merkle_hash_leaf(md, NULL, 0, pad_hash) != 0)
            return -1;
        for (int i = N; i < P; ++i)
            memcpy(nodes + (size_t)(P + i) * 32, pad_hash, 32);
    }

    /* 3. 自底向上构建内部节点 */
    for (int i = P - 1; i > 0; --i) {
        if (merkle_hash_internal(md, nodes + (size_t)(2 * i) * 32,
                nodes + (size_t)(2 * i + 1) * 32,
                nodes + (size_t)i * 32)
            != 0)
            return -1;
    }

    memcpy(root_out, nodes + 32 /* index 1 */, 32);
    return 0;
}
