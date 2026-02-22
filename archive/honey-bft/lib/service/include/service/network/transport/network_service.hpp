#pragma once

#include "peer_connection.hpp"
#include <mutex>
#include <string>
#include <unordered_map>

namespace Honey::BFT::Network {

struct NodeConfig {
    int32_t node_id;
    std::string host;
    uint16_t port;
};

class NetworkService : public std::enable_shared_from_this<NetworkService> {
public:
    NetworkService(int32_t my_id, uint16_t my_port, std::vector<NodeConfig> peers, Multiplexer& router)
        : my_node_id_(my_id)
        , my_port_(my_port)
        , peers_(std::move(peers))
        , router_(router)
        , acceptor_(io_ctx_)
        , work_guard_(asio::make_work_guard(io_ctx_))
    {
    }

    ~NetworkService() { stop(); }

    void start()
    {
        spdlog::info("[Network L1] Node {} starting on port {}", my_node_id_, my_port_);
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
        if (!running_.exchange(false))
            return;
        work_guard_.reset();
        io_ctx_.stop();
        if (io_thread_.joinable())
            io_thread_.join();
    }

    int32_t get_my_id() const { return my_node_id_; }

    // ==========================================
    // L3 协议层调用的发送接口 (零拷贝)
    // ==========================================
    void broadcast_raw(SharedPacket packet)
    {
        std::lock_guard lock(connections_mutex_);
        for (auto& [id, conn] : connections_) {
            conn->send_raw(packet); // shared_ptr 引用计数+1，数据不拷贝
        }
    }

    void unicast_raw(int32_t target_id, SharedPacket packet)
    {
        std::lock_guard lock(connections_mutex_);
        if (auto it = connections_.find(target_id); it != connections_.end()) {
            it->second->send_raw(packet);
        }
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

                // 握手：读取对方的 NodeID
                uint32_t peer_id_net = 0;
                co_await asio::async_read(socket, asio::buffer(&peer_id_net, 4), asio::use_awaitable);
                int32_t peer_id = ntohl(peer_id_net);

                spdlog::info("[Network L1] Node {} accepted connection from Node {}", my_node_id_, peer_id);
                register_connection(peer_id, std::move(socket));
            }
        } catch (const std::exception& e) {
            spdlog::error("[Network L1] Accept loop error: {}", e.what());
        }
    }

    asio::awaitable<void> connect_to_peer(NodeConfig peer)
    {
        using asio::ip::tcp;
        tcp::resolver resolver(io_ctx_);

        while (running_) {
            try {
                auto endpoints = co_await resolver.async_resolve(peer.host, std::to_string(peer.port), asio::use_awaitable);
                tcp::socket socket(io_ctx_);
                co_await asio::async_connect(socket, endpoints, asio::use_awaitable);

                // 握手：发送自己的 NodeID
                uint32_t my_id_net = htonl(my_node_id_);
                co_await asio::async_write(socket, asio::buffer(&my_id_net, 4), asio::use_awaitable);

                spdlog::info("[Network L1] Node {} connected to Node {}", my_node_id_, peer.node_id);
                register_connection(peer.node_id, std::move(socket));

                // 成功连接，退出重连循环
                co_return;
            } catch (const std::exception& e) {
                // 断线重连逻辑
                spdlog::debug("[Network L1] Node {} -> Node {} failed: {}. Retrying in 2s...", my_node_id_, peer.node_id, e.what());
                asio::steady_timer timer(io_ctx_, std::chrono::seconds(2));
                co_await timer.async_wait(asio::use_awaitable);
            }
        }
    }

    void register_connection(int32_t peer_id, asio::ip::tcp::socket socket)
    {
        auto conn = std::make_shared<PeerConnection>(std::move(socket), router_, peer_id);
        {
            std::lock_guard lock(connections_mutex_);
            connections_[peer_id] = conn;
        }
        // 启动连接内部的读写协程
        conn->start();
    }

    int32_t my_node_id_;
    uint16_t my_port_;
    std::vector<NodeConfig> peers_;

    Multiplexer& router_; // L2 路由器引用

    asio::io_context io_ctx_;
    asio::ip::tcp::acceptor acceptor_;
    asio::executor_work_guard<asio::io_context::executor_type> work_guard_;
    std::thread io_thread_;
    std::atomic<bool> running_ { true };

    std::mutex connections_mutex_;
    std::unordered_map<int32_t, std::shared_ptr<PeerConnection>> connections_;
};

} // namespace Honey::BFT::Network
