#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 解码查表结构
 * ⚠️  C99 flexible array member — include only from C translation units.
 */
struct isal_decode_tables {
    int K;
    unsigned char tables[]; /* 柔性数组：K*K*32 字节的解码表 */
};

struct isal_decode_tables*
isal_create_decode_tables(int K, const unsigned char* invert_matrix);
void isal_free_decode_tables(struct isal_decode_tables* tables);

int isal_invert_matrix(unsigned char* matrix, unsigned char* out_matrix,
    int size);

int isal_decode_data_direct(int block_size, int K,
    const unsigned char* tables_buffer,
    unsigned char** input, unsigned char** output);

int isal_decode_data(int block_size, int K,
    const struct isal_decode_tables* tables,
    unsigned char** input, unsigned char** output);

/**
 * RS 上下文结构（封装编码矩阵和编码表）
 */
struct isal_rs_context {
    int K;
    int N;
    unsigned char* encode_matrix; /* N*K 字节，malloc 分配 */
    unsigned char* encode_g_tbls; /* K*(N-K)*32 字节，malloc 分配 */
};

struct isal_rs_context* isal_rs_context_create(int K, int N);
void isal_rs_context_free(struct isal_rs_context* ctx);
const unsigned char*
isal_rs_context_encode_matrix(const struct isal_rs_context* ctx);
const unsigned char*
isal_rs_context_encode_g_tbls(const struct isal_rs_context* ctx);

#ifdef __cplusplus
}
#endif
