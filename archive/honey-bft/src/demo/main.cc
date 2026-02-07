#include "demo/honeybadger_node.hpp"
#include <chrono>
#include <iostream>
#include <spdlog/spdlog.h>
#include <thread>

using namespace Honey::Demo;

int main(int argc, char* argv[])
{
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <node_id>\n";
        return 1;
    }

    int node_id = std::atoi(argv[1]);
    spdlog::set_level(spdlog::level::info);

    spdlog::info("Node {} starting (N=4, f=1)", node_id);

    auto network = std::make_shared<LocalNetwork>();
    HoneyBadgerNode node(node_id, 4, 2, network);
    node.start();

    std::this_thread::sleep_for(std::chrono::seconds(1));

    for (int i = 0; i < 5; ++i) {
        std::string tx_data = "TX_" + std::to_string(node_id) + "_" + std::to_string(i);
        std::vector<Byte> tx;
        for (char c : tx_data) {
            tx.push_back(static_cast<Byte>(c));
        }
        node.submit_transaction(std::move(tx));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    spdlog::info("Node {} running...", node_id);
    std::this_thread::sleep_for(std::chrono::seconds(3));
    return 0;
}
