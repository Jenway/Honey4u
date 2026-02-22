#include "isal_memory_arena.h"
#include <stdlib.h>

struct isal_memory_arena* isal_memory_arena_create(int K, int N)
{
    if (K <= 0 || N <= K) {
        return NULL;
    }

    struct isal_memory_arena* arena = malloc(sizeof(struct isal_memory_arena));
    if (!arena) {
        return NULL;
    }

    arena->K = K;
    arena->N = N;
    arena->encode_ptrs = NULL;
    arena->decode_matrix = NULL;
    arena->decode_invert_matrix = NULL;
    arena->decode_input_ptrs = NULL;
    arena->decode_output_ptrs = NULL;
    arena->shard_indexes = NULL;
    arena->shard_ptrs = NULL;
    arena->block_size = 0;

    /* 编码用指针数组：N 个指针 */
    arena->encode_ptrs = (unsigned char**)malloc(sizeof(unsigned char*) * N);
    if (!arena->encode_ptrs) {
        goto fail;
    }

    /* 解码用临时矩阵 */
    arena->decode_matrix = (unsigned char*)malloc((size_t)K * K);
    if (!arena->decode_matrix) {
        goto fail;
    }

    arena->decode_invert_matrix = (unsigned char*)malloc((size_t)K * K);
    if (!arena->decode_invert_matrix) {
        goto fail;
    }

    /* 解码用指针数组 */
    arena->decode_input_ptrs = (unsigned char**)malloc(sizeof(unsigned char*) * K);
    if (!arena->decode_input_ptrs) {
        goto fail;
    }

    arena->decode_output_ptrs = (unsigned char**)malloc(sizeof(unsigned char*) * K);
    if (!arena->decode_output_ptrs) {
        goto fail;
    }

    arena->shard_indexes = (int*)malloc(sizeof(int) * K);
    if (!arena->shard_indexes) {
        goto fail;
    }

    arena->shard_ptrs = (const void**)malloc(sizeof(const void*) * K);
    if (!arena->shard_ptrs) {
        goto fail;
    }

    return arena;

fail:
    isal_memory_arena_free(arena);
    return NULL;
}

void isal_memory_arena_free(struct isal_memory_arena* arena)
{
    if (arena) {
        if (arena->encode_ptrs) {
            free((void*)arena->encode_ptrs);
        }
        if (arena->decode_matrix) {
            free(arena->decode_matrix);
        }
        if (arena->decode_invert_matrix) {
            free(arena->decode_invert_matrix);
        }
        if (arena->decode_input_ptrs) {
            free((void*)arena->decode_input_ptrs);
        }
        if (arena->decode_output_ptrs) {
            free((void*)arena->decode_output_ptrs);
        }
        if (arena->shard_indexes) {
            free(arena->shard_indexes);
        }
        if (arena->shard_ptrs) {
            free((void*)arena->shard_ptrs);
        }
        free(arena);
    }
}

int isal_memory_arena_fill_shards(struct isal_memory_arena* arena,
    const struct isal_shard_view* shards,
    int count)
{
    if (!arena || !shards || count <= 0 || count != arena->K) {
        return -1;
    }

    if (!arena->shard_indexes || !arena->shard_ptrs) {
        return -1;
    }

    int K = arena->K;

    size_t bs = shards[0].block_size;
    if (bs == 0) {
        return -1;
    }
    for (int i = 1; i < K; ++i) {
        if (shards[i].block_size != bs) {
            return -2;
        }
    }

    arena->block_size = bs;
    for (int i = 0; i < K; ++i) {
        arena->shard_indexes[i] = shards[i].index;
        arena->shard_ptrs[i] = shards[i].data;
    }

    return 0;
}
