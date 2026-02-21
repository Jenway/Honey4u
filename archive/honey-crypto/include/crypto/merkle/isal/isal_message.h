#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 打包消息（添加 4 字节 LE 长度前缀）
 * @param data 原始数据
 * @param len 原始数据长度
 * @param out_size 输出打包后的总大小（4 + len）
 * @return 打包后的缓冲区（malloc 分配），失败返回 NULL
 *
 * 调用者必须使用 free() 释放
 */
void* isal_pack_message(const void* data, size_t len, size_t* out_size);

/**
 * 解包消息（提取长度前缀和数据）
 * @param packed_data 打包的数据（含 4 字节前缀）
 * @param packed_size 打包数据的总大小
 * @param out_payload_size 输出实际数据大小
 * @return 指向 payload 的指针（指向 packed_data + 4，不需要释放）
 */
const void* isal_unpack_message(
    const void* packed_data,
    size_t packed_size,
    size_t* out_payload_size);

#ifdef __cplusplus
}
#endif
