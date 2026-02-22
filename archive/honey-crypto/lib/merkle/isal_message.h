#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 消息缓冲区结构（带 4 字节长度前缀）
 * 使用 C99 柔性数组存储 [len_prefix(4 bytes) | payload]
 *
 * ⚠️  C99 flexible array member — include only from C translation units.
 */
struct isal_message_buffer {
    size_t payload_size; /* payload 字节数（不含 4 字节前缀） */
    unsigned char storage[]; /* 柔性数组：4 + payload_size 字节 */
};

struct isal_message_buffer* isal_message_buffer_create(const void* data,
    size_t len);
const void* isal_message_buffer_payload(const struct isal_message_buffer* msg);
const void* isal_message_buffer_storage(const struct isal_message_buffer* msg);
size_t isal_message_buffer_storage_size(const struct isal_message_buffer* msg);
size_t isal_message_buffer_payload_size(const struct isal_message_buffer* msg);
void isal_message_buffer_free(struct isal_message_buffer* msg);
struct isal_message_buffer*
isal_message_buffer_from_packed(const void* packed_data, size_t packed_size);

#ifdef __cplusplus
}
#endif
