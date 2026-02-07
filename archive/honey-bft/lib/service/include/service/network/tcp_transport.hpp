#pragma once

#include "service/network/codec.hpp"
#include "service/network/message_bus.hpp"
#include <arpa/inet.h>
#include <exec/task.hpp>
#include <netinet/in.h>
#include <optional>
#include <span>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace Honey::BFT::Network {

class TcpTransport {
public:
    struct Config {
        int node_id;
        std::vector<std::pair<std::string, int>> peers;
    };

    explicit TcpTransport(Config config)
        : config_(std::move(config))
    {
    }

    auto run_server(MessageBus& bus) -> exec::task<void>;
    auto run_client(MessageBus& bus, ProtocolTag tag) -> exec::task<void>;

private:
    Config config_;
};

} // namespace Honey::BFT::Network
