#pragma once

#include <stddef.h>

// Opaque C types — complete definitions live in private src/merkle/isal/
// headers. Public C++ code interacts with them only through the C++ wrapper
// classes.
struct isal_message_buffer;
struct isal_shard_block;
struct isal_memory_arena;
struct isal_rs_context;
struct merkle_context;

// isal_shard_view is the only C type exposed publicly.
// It is a simple POD (no flexible arrays) and is safe for direct C++ use by
// callers.
#ifdef __cplusplus
extern "C" {
#endif

struct isal_shard_view {
    int index;
    const unsigned char* data;
    size_t block_size;
};

#ifdef __cplusplus
}
#endif
