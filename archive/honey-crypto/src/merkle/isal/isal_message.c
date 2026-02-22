#include "crypto/merkle/isal/isal_message.h"
#include <stdlib.h>
#include <string.h>

struct isal_message_buffer* isal_message_buffer_create(const void* data, size_t len)
{
    if (!data && len > 0) {
        return NULL;
    }

    size_t total_size = sizeof(struct isal_message_buffer) + 4 + len;
    struct isal_message_buffer* msg = malloc(total_size);
    if (!msg) {
        return NULL;
    }

    msg->payload_size = len;

    /* 写入长度前缀（Little Endian） */
    uint32_t len_le = (uint32_t)len;
    memcpy(msg->storage, &len_le, 4);

    /* 拷贝数据 */
    if (len > 0) {
        memcpy(msg->storage + 4, data, len);
    }

    return msg;
}

const void* isal_message_buffer_payload(const struct isal_message_buffer* msg)
{
    if (!msg) {
        return NULL;
    }
    return msg->storage + 4;
}

const void* isal_message_buffer_storage(const struct isal_message_buffer* msg)
{
    if (!msg) {
        return NULL;
    }
    return msg->storage;
}

size_t isal_message_buffer_storage_size(const struct isal_message_buffer* msg)
{
    if (!msg) {
        return 0;
    }
    return 4 + msg->payload_size;
}

void isal_message_buffer_free(struct isal_message_buffer* msg)
{
    if (msg) {
        free(msg);
    }
}

struct isal_message_buffer* isal_message_buffer_from_packed(
    const void* packed_data,
    size_t packed_size)
{
    if (!packed_data || packed_size < 4) {
        return NULL;
    }

    /* 读取长度前缀 */
    uint32_t payload_len = 0;
    memcpy(&payload_len, packed_data, 4);

    /* 验证大小一致性 */
    if (4 + payload_len != packed_size) {
        return NULL;
    }

    size_t total_size = sizeof(struct isal_message_buffer) + packed_size;
    struct isal_message_buffer* msg = malloc(total_size);
    if (!msg) {
        return NULL;
    }

    msg->payload_size = payload_len;
    memcpy(msg->storage, packed_data, packed_size);

    return msg;
}
