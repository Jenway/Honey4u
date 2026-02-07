#pragma once
#include <functional>
#include <map>
#include <memory>
#include <queue>
#include <spdlog/spdlog.h>

namespace Honey::Demo {
using Byte = std::byte;

struct NetworkMessage {
    int from_id;
    int to_id;
    std::vector<Byte> payload;
};

class LocalNetwork {
public:
    void register_node(int node_id, std::function<void(NetworkMessage)> handler)
    {
        handlers_[node_id] = std::move(handler);
    }

    void send(const NetworkMessage& msg)
    {
        if (msg.to_id == -1) {
            for (const auto& [node_id, handler] : handlers_) {
                if (node_id != msg.from_id) {
                    handler(msg);
                }
            }
        } else {
            auto it = handlers_.find(msg.to_id);
            if (it != handlers_.end()) {
                it->second(msg);
            }
        }
    }

private:
    std::map<int, std::function<void(NetworkMessage)>> handlers_;
};

class HoneyBadgerNode {
public:
    HoneyBadgerNode(int node_id, int n_nodes, int threshold,
        std::shared_ptr<LocalNetwork> network)
        : node_id_(node_id)
        , n_nodes_(n_nodes)
        , threshold_(threshold)
        , network_(std::move(network))
    {
    }

    void start()
    {
        network_->register_node(node_id_, [this](NetworkMessage msg) {
            handle_message(std::move(msg));
        });
    }

    void submit_transaction(std::vector<Byte> tx)
    {
        pending_transactions_.push(std::move(tx));
        if (pending_transactions_.size() >= 3) {
            start_epoch();
        }
    }

private:
    void start_epoch()
    {
        if (current_epoch_running_)
            return;

        std::vector<std::vector<Byte>> txs;
        while (!pending_transactions_.empty() && txs.size() < 5) {
            txs.push_back(std::move(pending_transactions_.front()));
            pending_transactions_.pop();
        }
        if (txs.empty())
            return;

        spdlog::info("Node {} starting epoch {}", node_id_, current_epoch_);
        for (const auto& tx : txs) {
            network_->send({ node_id_, -1, tx });
        }
        current_epoch_running_ = true;
        transactions_in_epoch_ = static_cast<int>(txs.size());
    }

    void handle_message(NetworkMessage)
    {
        received_transactions_count_++;
        if (current_epoch_running_ && received_transactions_count_ >= n_nodes_ * transactions_in_epoch_) {
            spdlog::info("Node {} outputting block {}", node_id_, current_epoch_);
            current_epoch_++;
            current_epoch_running_ = false;
            received_transactions_count_ = 0;
        }
    }

    int node_id_, n_nodes_, threshold_;
    std::shared_ptr<LocalNetwork> network_;
    int current_epoch_ = 0;
    bool current_epoch_running_ = false;
    int transactions_in_epoch_ = 0;
    int received_transactions_count_ = 0;
    std::queue<std::vector<Byte>> pending_transactions_;
};

}
