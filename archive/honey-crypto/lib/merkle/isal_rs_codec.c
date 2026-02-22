#include "isal_rs_codec.h"
#include "isal_message.h"
#include "isal_rs_tables.h"
#include <isa-l/erasure_code.h>
#include <stdalign.h>
#include <stdlib.h>
#include <string.h>

/* 对齐到 32 字节边界（用于 SIMD） */
#define ALIGN_SIZE 32
#define ALIGN_UP(x, align) (((x) + (align) - 1) & ~((align) - 1))

/**
 * 分配对齐内存（C11 aligned_alloc 或回退到手动对齐）
 */
static void* aligned_malloc(size_t size, size_t alignment)
{
#if defined(_WIN32)
    return _aligned_malloc(size, alignment);
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
    size_t aligned_size = ALIGN_UP(size, alignment);
    return aligned_alloc(alignment, aligned_size);
#else
    void* ptr = malloc(size + alignment);
    if (!ptr)
        return NULL;
    size_t offset = alignment - ((uintptr_t)ptr % alignment);
    return (char*)ptr + offset;
#endif
}

static void aligned_free_internal(void* ptr)
{
#if defined(_WIN32)
    _aligned_free(ptr);
#else
    free(ptr);
#endif
}

void isal_aligned_free(void* ptr)
{
    if (ptr) {
        aligned_free_internal(ptr);
    }
}

/* ============================================================================
   编码实现
   ============================================================================
 */

struct isal_shard_block*
isal_rs_encode_create(const struct isal_memory_arena* arena,
    const unsigned char* encode_tables,
    const void* input_data, size_t input_len)
{
    if (!arena || arena->K <= 0 || arena->N <= arena->K || !encode_tables || !input_data) {
        return NULL;
    }

    int K = arena->K;
    int N = arena->N;

    /* 1. 计算 block_size（含 4 字节长度前缀，对齐到 32 字节） */
    size_t payload_len = 4 + input_len;
    size_t block_size = (payload_len + K - 1) / K;
    block_size = ALIGN_UP(block_size, ALIGN_SIZE);

    size_t total_size = (size_t)N * block_size;

    /* 2. 分配对齐内存 */
    void* storage = aligned_malloc(total_size, ALIGN_SIZE);
    if (!storage) {
        return NULL;
    }

    /* 3. 初始化：清零 + 写入长度前缀 + 拷贝数据 */
    memset(storage, 0, total_size);

    uint32_t len_le = (uint32_t)input_len;
    memcpy(storage, &len_le, 4);
    memcpy((char*)storage + 4, input_data, input_len);

    /* 4. 使用 arena 中预分配的指针数组 */
    unsigned char** ptrs = arena->encode_ptrs;
    for (int i = 0; i < N; ++i) {
        ptrs[i] = (unsigned char*)storage + (size_t)i * block_size;
    }

    /* 5. 执行纠删码编码 */
    ec_encode_data((int)block_size, K, N - K, (unsigned char*)encode_tables,
        ptrs, ptrs + K);

    /* 6. 创建返回结构 */
    struct isal_shard_block* block = (struct isal_shard_block*)malloc(sizeof(struct isal_shard_block));
    if (!block) {
        aligned_free_internal(storage);
        return NULL;
    }

    block->storage = storage;
    block->block_size = block_size;
    block->K = K;
    block->N = N;

    return block;
}

void isal_shard_block_free(struct isal_shard_block* block)
{
    if (block) {
        if (block->storage) {
            aligned_free_internal(block->storage);
        }
        free(block);
    }
}

/* ============================================================================
   解码实现
   ============================================================================
 */

int isal_rs_decode_into(const struct isal_memory_arena* arena,
    const unsigned char* encode_matrix, void* output,
    size_t* payload_size)
{
    if (!arena || arena->K <= 0 || arena->block_size == 0 || !encode_matrix || !arena->shard_indexes || !arena->shard_ptrs || !output || !payload_size) {
        return -1;
    }

    int K = arena->K;
    size_t block_size = arena->block_size;
    const int* shard_indexes = arena->shard_indexes;
    const void* const* shard_data = (const void* const*)arena->shard_ptrs;

    /* 1. 检查 Fast Path（前 K 个连续分片） */
    int is_fast_path = 1;
    for (int i = 0; i < K; ++i) {
        if (shard_indexes[i] != i) {
            is_fast_path = 0;
            break;
        }
    }

    /* 2. Fast Path：直接拷贝数据 */
    if (is_fast_path) {
        for (int i = 0; i < K; ++i) {
            memcpy((char*)output + (size_t)i * block_size, shard_data[i],
                block_size);
        }
        uint32_t len;
        memcpy(&len, output, 4);
        *payload_size = len;
        return 0;
    }

    /* 3. Slow Path：纠删码解码 */

    /* 3.1 构建解码矩阵 */
    unsigned char* decode_matrix = arena->decode_matrix;
    for (int i = 0; i < K; ++i) {
        int src_idx = shard_indexes[i];
        memcpy(decode_matrix + (size_t)i * K, encode_matrix + (size_t)src_idx * K,
            (size_t)K);
    }

    /* 3.2 矩阵反演 */
    unsigned char* invert_matrix = arena->decode_invert_matrix;
    if (isal_invert_matrix(decode_matrix, invert_matrix, K) < 0) {
        return -2;
    }

    /* 3.3 创建解码表 */
    struct isal_decode_tables* tables = isal_create_decode_tables(K, invert_matrix);
    if (!tables) {
        return -1;
    }

    /* 3.4 设置输入/输出指针（直接指向调用方缓冲区，零拷贝） */
    unsigned char** input_ptrs = arena->decode_input_ptrs;
    unsigned char** output_ptrs = arena->decode_output_ptrs;
    for (int i = 0; i < K; ++i) {
        input_ptrs[i] = (unsigned char*)shard_data[i];
        output_ptrs[i] = (unsigned char*)output + (size_t)i * block_size;
    }

    /* 3.5 执行解码 */
    int decode_ret = isal_decode_data_direct((int)block_size, K, tables->tables,
        input_ptrs, output_ptrs);

    isal_free_decode_tables(tables);

    if (decode_ret < 0) {
        return -1;
    }

    /* 3.6 提取 payload 大小 */
    uint32_t len;
    memcpy(&len, output, 4);
    *payload_size = len;
    return 0;
}

struct isal_message_buffer*
isal_rs_decode_create(const struct isal_memory_arena* arena,
    const unsigned char* encode_matrix)
{
    if (!arena || arena->K <= 0 || arena->block_size == 0 || !encode_matrix) {
        return NULL;
    }

    int K = arena->K;
    size_t block_size = arena->block_size;

    /* 1. 分配临时解码缓冲区 */
    size_t decode_size = (size_t)K * block_size;
    void* temp_buffer = malloc(decode_size);
    if (!temp_buffer) {
        return NULL;
    }

    /* 2. 解码到临时缓冲区 */
    size_t payload_size = 0;
    int status = isal_rs_decode_into(arena, encode_matrix, temp_buffer, &payload_size);
    if (status != 0) {
        free(temp_buffer);
        return NULL;
    }

    /* 3. 创建 message buffer（包含 4 字节前缀 + payload） */
    size_t storage_size = 4 + payload_size;
    size_t total_size = sizeof(struct isal_message_buffer) + storage_size;
    struct isal_message_buffer* msg_buffer = (struct isal_message_buffer*)malloc(total_size);
    if (!msg_buffer) {
        free(temp_buffer);
        return NULL;
    }

    msg_buffer->payload_size = payload_size;

    /* 4. 复制数据：从临时缓冲区的前 storage_size 字节（已包含长度前缀） */
    memcpy(msg_buffer->storage, temp_buffer, storage_size);

    free(temp_buffer);
    return msg_buffer;
}
