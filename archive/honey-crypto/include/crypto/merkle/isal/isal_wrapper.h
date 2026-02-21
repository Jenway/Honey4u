#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 解码查表结构
 */
struct isal_decode_tables {
    int K; /* 数据块数 */
    unsigned char tables[]; /* 柔性数组：K*K*32 字节的解码表 */
};

/**
 * 从反演矩阵创建解码查表
 * @param K 数据块数
 * @param invert_matrix 反演矩阵指针 (K*K 字节)
 * @return 指向已分配的解码表，失败返回 NULL
 */
struct isal_decode_tables* isal_create_decode_tables(
    int K, const unsigned char* invert_matrix);

/**
 * 释放解码查表
 */
void isal_free_decode_tables(struct isal_decode_tables* tables);

/* ============================================================================
   编码/解码操作
   ============================================================================ */

/**
 * 进行矩阵反演（用于解码）
 * @param matrix 输入矩阵 (K*K 字节，会被修改)
 * @param out_matrix 输出反演矩阵 (K*K 字节)
 * @param size 矩阵大小 (K)
 * @return 0 成功，-1 失败
 */
int isal_invert_matrix(unsigned char* matrix, unsigned char* out_matrix, int size);

/**
 * 执行 Reed-Solomon 解码（直接使用缓冲区）
 * 此函数允许调用者直接提供解码表缓冲区，避免创建临时结构
 * @param block_size 每个块的字节数
 * @param K 数据块数
 * @param tables_buffer 解码表缓冲区指针（K*K*32 字节，由 isal_create_decode_tables 创建或直接提供）
 * @param input 输入数据指针数组（K 个指针）
 * @param output 输出数据指针数组（K 个指针）
 * @return 0 成功，-1 失败
 */
int isal_decode_data_direct(
    int block_size, int K,
    const unsigned char* tables_buffer,
    unsigned char** input, unsigned char** output);

/**
 * 执行 Reed-Solomon 解码
 * @param block_size 每个块的字节数
 * @param K 数据块数
 * @param tables 解码查表指针（由 isal_create_decode_tables 创建）
 * @param input 输入数据指针数组（K 个指针）
 * @param output 输出数据指针数组（K 个指针）
 * @return 0 成功，-1 失败
 */
int isal_decode_data(
    int block_size, int K,
    const struct isal_decode_tables* tables,
    unsigned char** input, unsigned char** output);

/* ============================================================================
   RsContext 统一创建（优先级 1）
   ============================================================================ */

/**
 * RS 上下文结构（封装编码矩阵和编码表）
 */
struct isal_rs_context {
    int K;
    int N;
    unsigned char* encode_matrix; /* N*K 字节，malloc 分配 */
    unsigned char* encode_g_tbls; /* K*(N-K)*32 字节，malloc 分配 */
};

/**
 * 一步创建 RS 上下文（封装矩阵生成和编码表初始化）
 * @param K 数据分片数
 * @param N 总分片数
 * @return RS 上下文，失败返回 NULL
 *
 * 调用者必须使用 isal_rs_context_free 释放
 */
struct isal_rs_context* isal_rs_context_create(int K, int N);

/**
 * 释放 RS 上下文
 */
void isal_rs_context_free(struct isal_rs_context* ctx);

#ifdef __cplusplus
}
#endif
