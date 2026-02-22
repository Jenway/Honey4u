#pragma once

#include "wire_format.hpp"
#include <asio.hpp>

#include <asio/co_spawn.hpp>
#include <asio/coroutine.hpp>
#include <asio/experimental/awaitable_operators.hpp>
#include <asio/experimental/channel.hpp>
#include <memory>
#include <spdlog/spdlog.h>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

namespace Honey::BFT::Network {

// 提前声明 L2 的路由器接口 (L1 只需知道把它推给谁)
class Multiplexer;

using SharedPacket = std::shared_ptr<const std::vector<std::byte>>;
using SharedPayload = std::shared_ptr<const std::vector<std::byte>>;

class PeerConnection : public std::enable_shared_from_this<PeerConnection> {
public:
    PeerConnection(asio::ip::tcp::socket socket, Multiplexer& router, int32_t peer_id)
        : socket_(std::move(socket))
        , router_(router)
        , peer_id_(peer_id)
        , tx_queue_(socket_.get_executor(), 1024)
    {
    }

    // 启动读写分离的双协程
    void start()
    {
        asio::co_spawn(socket_.get_executor(), read_loop(), asio::detached);
        asio::co_spawn(socket_.get_executor(), write_loop(), asio::detached);
    }

    // 线程安全/协程安全的发送接口 (非阻塞)
    void send_raw(SharedPacket packet)
    {
        // 尝试推入发送队列。如果队列满则丢弃或阻塞(此处使用 try_send 非阻塞机制)
        tx_queue_.try_send(asio::error_code {}, std::move(packet));
    }

    void close()
    {
        asio::error_code ec;
        socket_.close(ec);
        tx_queue_.cancel();
    }

private:
    // ==========================================
    // 后台写循环：唯一的 async_write 调用点
    // ==========================================
    asio::awaitable<void> write_loop()
    {
        try {
            while (true) {
                // 1. 从队列取出准备好的二进制包
                auto packet = co_await tx_queue_.async_receive(asio::use_awaitable);

                // 2. 串行盲写底层 Socket ( packet 内已经包含了转换好端序的 WireHeader )
                co_await asio::async_write(socket_, asio::buffer(*packet), asio::use_awaitable);
            }
        } catch (const std::exception& e) {
            spdlog::debug("[Network L1] Peer {} Write loop exited: {}", peer_id_, e.what());
            close();
        }
    }

    // ==========================================
    // 后台读循环：防 OOM 熔断与粘包处理
    // ==========================================
    asio::awaitable<void> read_loop()
    {
        try {
            while (true) {
                WireHeader header;

                // 1. 精确读取 16 字节头部
                co_await asio::async_read(socket_, asio::buffer(&header, sizeof(header)), asio::use_awaitable);

                // 2. 网络字节序转换
                header.payload_len = ntohl(header.payload_len);
                header.session_id = ntohl(header.session_id);
                header.instance_id = ntohl(header.instance_id);
                header.sender_id = ntohl(header.sender_id);

                // 3. 💥 硬件级防攻击熔断
                if (header.payload_len > MAX_PAYLOAD_SIZE) {
                    spdlog::critical("[Network L1] OOM Protection triggered! Peer {} sent {} bytes. Dropping connection.",
                        peer_id_, header.payload_len);
                    close();
                    co_return;
                }

                // 4. 读取指定长度的载荷
                auto payload = std::make_shared<std::vector<std::byte>>(header.payload_len);
                if (header.payload_len > 0) {
                    co_await asio::async_read(socket_, asio::buffer(*payload), asio::use_awaitable);
                }

                // 5. 移交给 L2 路由器 (我们会在实现 L2 时补全这个方法)
                // router_.route_incoming(header, std::move(payload));
            }
        } catch (const std::exception& e) {
            spdlog::debug("[Network L1] Peer {} Read loop exited: {}", peer_id_, e.what());
            close();
        }
    }

    asio::ip::tcp::socket socket_;
    Multiplexer& router_;
    int32_t peer_id_;
    asio::experimental::channel<void(asio::error_code, SharedPacket)> tx_queue_;
};

} // namespace Honey::BFT::Network
