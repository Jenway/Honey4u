#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * 消息缓冲区结构（带 4 字节长度前缀）
 * 使用 C99 柔性数组存储 [len_prefix(4 bytes) | payload]
 */
struct isal_message_buffer {
    size_t payload_size; /* payload 字节数（不含 4 字节前缀） */
    unsigned char storage[]; /* 柔性数组：4 + payload_size 字节 */
};

/**
 * 创建消息缓冲区（自动添加 4 字节 LE 长度前缀）
 * @param data 原始数据
 * @param len 原始数据长度
 * @return 消息缓冲区，失败返回 NULL
 *
 * 调用者必须使用 isal_message_buffer_free() 释放
 */
struct isal_message_buffer* isal_message_buffer_create(const void* data, size_t len);

/**
 * 获取 payload 指针（跳过 4 字节前缀）
 * @param msg 消息缓冲区
 * @return payload 指针，失败返回 NULL
 */
const void* isal_message_buffer_payload(const struct isal_message_buffer* msg);

/**
 * 获取完整的 storage 指针（包含 4 字节前缀）
 * @param msg 消息缓冲区
 * @return storage 指针
 */
const void* isal_message_buffer_storage(const struct isal_message_buffer* msg);

/**
 * 获取完整的 storage 大小（4 + payload_size）
 * @param msg 消息缓冲区
 * @return storage 大小
 */
size_t isal_message_buffer_storage_size(const struct isal_message_buffer* msg);

/**
 * 释放消息缓冲区
 */
void isal_message_buffer_free(struct isal_message_buffer* msg);

/**
 * 从已打包的数据创建消息缓冲区（不验证长度前缀）
 * @param packed_data 打包的数据（含 4 字节前缀）
 * @param packed_size 打包数据的总大小
 * @return 消息缓冲区，失败返回 NULL
 */
struct isal_message_buffer* isal_message_buffer_from_packed(
    const void* packed_data,
    size_t packed_size);

#ifdef __cplusplus
}
#endif
