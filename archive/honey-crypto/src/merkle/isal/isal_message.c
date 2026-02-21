#include "crypto/merkle/isal/isal_wrapper.h"
#include <isa-l/erasure_code.h>
#include <stdlib.h>
#include <string.h>

void* isal_pack_message(const void* data, size_t len, size_t* out_size)
{
    if (!data && len > 0) {
        return NULL;
    }

    size_t total_size = 4 + len;
    void* packed = malloc(total_size);
    if (!packed) {
        return NULL;
    }

    /* 写入长度前缀（Little Endian） */
    uint32_t len_le = (uint32_t)len;
    memcpy(packed, &len_le, 4);

    /* 拷贝数据 */
    if (len > 0) {
        memcpy((char*)packed + 4, data, len);
    }

    if (out_size) {
        *out_size = total_size;
    }

    return packed;
}

const void* isal_unpack_message(
    const void* packed_data,
    size_t packed_size,
    size_t* out_payload_size)
{
    if (!packed_data || packed_size < 4) {
        return NULL;
    }

    /* 读取长度前缀 */
    uint32_t len = 0;
    memcpy(&len, packed_data, 4);

    if (out_payload_size) {
        *out_payload_size = len;
    }

    /* 返回 payload 指针 */
    return (const char*)packed_data + 4;
}
