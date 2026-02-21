#include "crypto/merkle/isal/isal_wrapper.h"
#include <isa-l/erasure_code.h>
#include <stdlib.h>
#include <string.h>

/* ============================================================================
   解码查表实现
   ============================================================================ */

struct isal_decode_tables* isal_create_decode_tables(
    int K, const unsigned char* invert_matrix)
{
    if (K <= 0 || !invert_matrix) {
        return NULL;
    }

    size_t tables_size = K * K * 32;
    size_t total_size = sizeof(struct isal_decode_tables) + tables_size;

    struct isal_decode_tables* tables = malloc(total_size);
    if (!tables) {
        return NULL;
    }

    tables->K = K;

    /* 初始化解码表到柔性数组中 */
    ec_init_tables(K, K, (unsigned char*)invert_matrix, tables->tables);

    return tables;
}

void isal_free_decode_tables(struct isal_decode_tables* tables)
{
    if (tables) {
        free(tables);
    }
}

/* ============================================================================
   编码/解码辅助函数
   ============================================================================ */

int isal_invert_matrix(unsigned char* matrix, unsigned char* out_matrix, int size)
{
    if (!matrix || !out_matrix || size <= 0) {
        return -1;
    }
    return gf_invert_matrix(matrix, out_matrix, size);
}

int isal_decode_data_direct(
    int block_size, int K,
    const unsigned char* tables_buffer,
    unsigned char** input, unsigned char** output)
{
    if (!tables_buffer) {
        return -1;
    }

    ec_encode_data(
        block_size, K, K,
        (unsigned char*)tables_buffer,
        input, output);

    return 0;
}

struct isal_rs_context* isal_rs_context_create(int K, int N)
{
    if (K <= 0 || N <= K) {
        return NULL;
    }

    struct isal_rs_context* ctx = malloc(sizeof(struct isal_rs_context));
    if (!ctx) {
        return NULL;
    }

    ctx->K = K;
    ctx->N = N;

    /* 1. 生成编码矩阵 */
    size_t matrix_size = (size_t)N * (size_t)K;
    ctx->encode_matrix = malloc(matrix_size);
    if (!ctx->encode_matrix) {
        free(ctx);
        return NULL;
    }

    gf_gen_cauchy1_matrix(ctx->encode_matrix, N, K);

    /* 2. 初始化编码表 */
    size_t tables_size = (size_t)K * (size_t)(N - K) * 32;
    ctx->encode_g_tbls = malloc(tables_size);
    if (!ctx->encode_g_tbls) {
        free(ctx->encode_matrix);
        free(ctx);
        return NULL;
    }

    unsigned char* parity_matrix = ctx->encode_matrix + K * K;
    ec_init_tables(K, N - K, parity_matrix, ctx->encode_g_tbls);

    return ctx;
}

void isal_rs_context_free(struct isal_rs_context* ctx)
{
    if (ctx) {
        if (ctx->encode_matrix) {
            free(ctx->encode_matrix);
        }
        if (ctx->encode_g_tbls) {
            free(ctx->encode_g_tbls);
        }
        free(ctx);
    }
}
