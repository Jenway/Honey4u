#include "service/network/tcp_transport.hpp"
#include <cstring>
#include <thread>

namespace Honey::BFT::Network {

namespace {
    constexpr size_t HEADER_SIZE = 9;
}

static bool read_exact(int fd, std::vector<std::byte>& buffer, size_t len)
{
    buffer.resize(len);
    size_t read_total = 0;
    while (read_total < len) {
        auto n = ::recv(fd, buffer.data() + read_total, len - read_total, 0);
        if (n <= 0)
            return false;
        read_total += static_cast<size_t>(n);
    }
    return true;
}

static bool write_all(int fd, std::span<const std::byte> data)
{
    size_t total = 0;
    while (total < data.size()) {
        auto n = ::send(fd, data.data() + total, data.size() - total, 0);
        if (n <= 0)
            return false;
        total += static_cast<size_t>(n);
    }
    return true;
}

auto TcpTransport::run_server(MessageBus& bus) -> exec::task<void>
{
    const auto& [host, port] = config_.peers.at(config_.node_id);
    int server_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        throw std::runtime_error("Failed to create server socket");
    }

    sockaddr_in addr {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    addr.sin_addr.s_addr = inet_addr(host.c_str());

    int reuse = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    if (::bind(server_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(server_fd);
        throw std::runtime_error("Failed to bind server socket");
    }

    if (::listen(server_fd, static_cast<int>(config_.peers.size())) < 0) {
        ::close(server_fd);
        throw std::runtime_error("Failed to listen on server socket");
    }

    std::thread([server_fd, &bus]() {
        while (true) {
            sockaddr_in client {};
            socklen_t len = sizeof(client);
            int client_fd = ::accept(server_fd, reinterpret_cast<sockaddr*>(&client), &len);
            if (client_fd < 0) {
                continue;
            }
            std::thread([client_fd, &bus]() {
                std::vector<std::byte> header;
                std::vector<std::byte> payload;
                while (read_exact(client_fd, header, HEADER_SIZE)) {
                    auto header_opt = decode_header(std::span(header));
                    if (!header_opt) {
                        break;
                    }
                    auto [tag, size, target] = *header_opt;
                    if (size == 0) {
                        bus.push(Frame { .tag = tag, .target = target, .payload = {}, .direction = FrameDirection::Inbound });
                        continue;
                    }
                    if (!read_exact(client_fd, payload, size)) {
                        break;
                    }
                    bus.push(Frame { .tag = tag, .target = target, .payload = std::move(payload), .direction = FrameDirection::Inbound });
                }
                ::close(client_fd);
            }).detach();
        }
    }).detach();

    co_return;
}

auto TcpTransport::run_client(MessageBus& bus, ProtocolTag tag) -> exec::task<void>
{
    std::vector<int> sockets(config_.peers.size(), -1);
    for (size_t i = 0; i < config_.peers.size(); ++i) {
        if (static_cast<int>(i) == config_.node_id) {
            continue;
        }
        const auto& [host, port] = config_.peers[i];
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            continue;
        }
        sockaddr_in addr {};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(port));
        addr.sin_addr.s_addr = inet_addr(host.c_str());
        if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
            ::close(fd);
            continue;
        }
        sockets[i] = fd;
    }

    auto& stream = bus.subscribe(tag);
    while (auto frame_opt = co_await stream.next()) {
        if (frame_opt->direction == FrameDirection::Inbound) {
            continue;
        }
        auto data = encode_frame(*frame_opt);
        if (frame_opt->target == -1) {
            for (auto fd : sockets) {
                if (fd >= 0) {
                    write_all(fd, data);
                }
            }
        } else if (frame_opt->target >= 0 && frame_opt->target < static_cast<int>(sockets.size())) {
            auto fd = sockets[frame_opt->target];
            if (fd >= 0) {
                write_all(fd, data);
            }
        }
    }
    co_return;
}

} // namespace Honey::BFT::Network
