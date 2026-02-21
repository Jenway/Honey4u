#pragma once

#include "service/network/blocking_queue.hpp"
#include "service/network/message_bus.hpp"
#include "service/network/protocol_codec.hpp"
#include <asio.hpp>
#include <asio/awaitable.hpp>
#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/use_awaitable.hpp>
#include <memory>
#include <spdlog/spdlog.h>
#include <string>
#include <unordered_map>

namespace Honey::BFT::Network {

/**
 * @brief 节点配置
 */
struct NodeConfig {
    int node_id;
    std::string host;
    uint16_t port;
};

/**
 * @brief 网络服务：TCP 连接管理和消息传输
 *
 * 职责（仅）：
 * - TCP 连接管理（监听、连接、重连）
 * - 消息的发送和接收
 * - 使用 ProtocolCodec 处理序列化
 *
 * 不负责：序列化的细节实现
 */
class NetworkService : public std::enable_shared_from_this<NetworkService> {
public:
    NetworkService(int my_node_id, uint16_t my_port, std::vector<NodeConfig> peers)
        : my_node_id_(my_node_id)
        , my_port_(my_port)
        , peers_(std::move(peers))
        , acceptor_(io_ctx_)
        , work_guard_(asio::make_work_guard(io_ctx_))
    {
    }

    ~NetworkService()
    {
        stop();
    }

    void start()
    {
        spdlog::info("[Network] Node {} listening on port {}", my_node_id_, my_port_);
        start_accept();

        for (const auto& peer : peers_) {
            if (peer.node_id != my_node_id_) {
                asio::co_spawn(io_ctx_, connect_to_peer(peer), asio::detached);
            }
        }

        io_thread_ = std::thread([this] { io_ctx_.run(); });
    }

    void stop()
    {
        if (!running_.exchange(false)) {
            return;
        }

        recv_stream_.close();
        work_guard_.reset();
        io_ctx_.stop();

        if (io_thread_.joinable()) {
            io_thread_.join();
        }

        spdlog::info("[Network] Node {} stopped", my_node_id_);
    }

    void send_to(int target_id, const Frame& frame)
    {
        asio::post(io_ctx_, [this, target_id, frame]() mutable {
            asio::co_spawn(io_ctx_, send_frame(target_id, frame), asio::detached);
        });
    }

    void broadcast(const Frame& frame)
    {
        for (const auto& peer : peers_) {
            if (peer.node_id != my_node_id_) {
                send_to(peer.node_id, frame);
            }
        }
    }

    auto& receive_stream()
    {
        return recv_stream_;
    }

private:
    void start_accept()
    {
        using asio::ip::tcp;
        tcp::endpoint endpoint(tcp::v4(), my_port_);
        acceptor_.open(endpoint.protocol());
        acceptor_.set_option(tcp::acceptor::reuse_address(true));
        acceptor_.bind(endpoint);
        acceptor_.listen();
        asio::co_spawn(io_ctx_, accept_loop(), asio::detached);
    }

    asio::awaitable<void> accept_loop()
    {
        try {
            while (running_) {
                auto socket = co_await acceptor_.async_accept(asio::use_awaitable);
                asio::co_spawn(io_ctx_, handle_connection(std::move(socket)), asio::detached);
            }
        } catch (const std::exception& e) {
            spdlog::error("[Network] Accept: {}", e.what());
        }
    }

    asio::awaitable<void> handle_connection(asio::ip::tcp::socket socket)
    {
        try {
            uint32_t peer_id_net = 0;
            co_await asio::async_read(socket, asio::buffer(&peer_id_net, 4), asio::use_awaitable);
            int peer_id = static_cast<int>(ntohl(peer_id_net));

            spdlog::debug("[Network] Node {} <- Node {}", my_node_id_, peer_id);

            while (running_) {
                uint32_t msg_len_net = 0;
                co_await asio::async_read(socket, asio::buffer(&msg_len_net, 4), asio::use_awaitable);
                uint32_t msg_len = ntohl(msg_len_net);

                std::vector<std::byte> msg_data(msg_len);
                co_await asio::async_read(socket, asio::buffer(msg_data), asio::use_awaitable);

                try {
                    if (auto frame = ProtocolCodec::decode(msg_data, peer_id)) {
                        frame->direction = FrameDirection::Inbound;
                        recv_stream_.push(std::move(*frame));
                    } else {
                        spdlog::warn("[Network] Decode error from node {}", peer_id);
                    }
                } catch (const std::exception& e) {
                    spdlog::warn("[Network] Decode error: {}", e.what());
                }
            }
        } catch (const std::exception&) {
            // Connection closed
        }
    }

    asio::awaitable<void> connect_to_peer(NodeConfig peer)
    {
        using asio::ip::tcp;
        tcp::resolver resolver(io_ctx_);

        while (running_) {
            try {
                auto endpoints = co_await resolver.async_resolve(
                    peer.host, std::to_string(peer.port), asio::use_awaitable);

                asio::ip::tcp::socket socket(io_ctx_);
                co_await asio::async_connect(socket, endpoints, asio::use_awaitable);

                uint32_t my_id_net = htonl(static_cast<uint32_t>(my_node_id_));
                co_await asio::async_write(socket, asio::buffer(&my_id_net, 4), asio::use_awaitable);

                spdlog::debug("[Network] Node {} -> Node {}", my_node_id_, peer.node_id);

                {
                    std::lock_guard lock(connections_mutex_);
                    connections_[peer.node_id] = std::move(socket);
                }

                co_return;
            } catch (const std::exception& e) {
                spdlog::debug("[Network] Connecting to node {}: {}, retry in 2s", peer.node_id, e.what());

                asio::steady_timer timer(io_ctx_);
                timer.expires_after(std::chrono::seconds(2));
                co_await timer.async_wait(asio::use_awaitable);
            }
        }
    }

    asio::awaitable<void> send_frame(int target_id, const Frame& frame)
    {
        try {
            auto msg_data = ProtocolCodec::encode(frame);
            uint32_t msg_len = static_cast<uint32_t>(msg_data.size());

            asio::ip::tcp::socket* socket_ptr = nullptr;
            {
                std::lock_guard lock(connections_mutex_);
                auto it = connections_.find(target_id);
                if (it != connections_.end()) {
                    socket_ptr = &it->second;
                } else {
                    co_return;
                }
            }

            uint32_t msg_len_net = htonl(msg_len);
            co_await asio::async_write(*socket_ptr, asio::buffer(&msg_len_net, 4), asio::use_awaitable);
            co_await asio::async_write(*socket_ptr, asio::buffer(msg_data), asio::use_awaitable);

        } catch (const std::exception& e) {
            spdlog::error("[Network] Send to {} failed: {}", target_id, e.what());
            {
                std::lock_guard lock(connections_mutex_);
                connections_.erase(target_id);
            }
        }
    }

    int my_node_id_;
    uint16_t my_port_;
    std::vector<NodeConfig> peers_;

    asio::io_context io_ctx_;
    asio::ip::tcp::acceptor acceptor_;
    asio::executor_work_guard<asio::io_context::executor_type> work_guard_;
    std::thread io_thread_;

    std::atomic<bool> running_ { true };
    std::mutex connections_mutex_;
    std::unordered_map<int, asio::ip::tcp::socket> connections_;

    BlockingQueueStream<Frame> recv_stream_;
};

} // namespace Honey::BFT::Network
