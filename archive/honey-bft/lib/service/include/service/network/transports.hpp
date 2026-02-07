#pragma once

#include "service/network/codec.hpp"
#include "service/network/message_bus.hpp"
#include "service/network/protocol_codecs.hpp"
#include <exec/task.hpp>

namespace Honey::BFT::Network {

class RBCTransport {
public:
    RBCTransport(MessageBus& bus, int instance_id)
        : bus_(bus)
        , instance_id_(instance_id)
    {
    }

    auto broadcast(const RBC::RBCMessage& msg) -> exec::task<void>
    {
        Frame frame {
            .tag = ProtocolTag::Rbc,
            .target = -1,
            .payload = encode_rbc_envelope(instance_id_, msg)
        };
        bus_.push(std::move(frame));
        co_return;
    }

    auto unicast(int target, const RBC::RBCMessage& msg) -> exec::task<void>
    {
        Frame frame {
            .tag = ProtocolTag::Rbc,
            .target = target,
            .payload = encode_rbc_envelope(instance_id_, msg)
        };
        bus_.push(std::move(frame));
        co_return;
    }

private:
    MessageBus& bus_;
    int instance_id_;
};

class PRBCTransport {
public:
    PRBCTransport(MessageBus& bus, int instance_id)
        : bus_(bus)
        , instance_id_(instance_id)
    {
    }

    auto broadcast(const PRBC::PRBCMessage& msg) -> exec::task<void>
    {
        Frame frame {
            .tag = ProtocolTag::Prbc,
            .target = -1,
            .payload = encode_prbc_envelope(instance_id_, msg)
        };
        bus_.push(std::move(frame));
        co_return;
    }

    auto unicast(int target, const PRBC::PRBCMessage& msg) -> exec::task<void>
    {
        Frame frame {
            .tag = ProtocolTag::Prbc,
            .target = target,
            .payload = encode_prbc_envelope(instance_id_, msg)
        };
        bus_.push(std::move(frame));
        co_return;
    }

private:
    MessageBus& bus_;
    int instance_id_;
};

class BATransport {
public:
    BATransport(MessageBus& bus, int instance_id)
        : bus_(bus)
        , instance_id_(instance_id)
    {
    }

    auto broadcast(const BA::Message& msg) -> exec::task<void>
    {
        Frame frame {
            .tag = ProtocolTag::Ba,
            .target = -1,
            .payload = encode_ba_envelope(instance_id_, msg)
        };
        bus_.push(std::move(frame));
        co_return;
    }

    auto unicast(int target, const BA::Message& msg) -> exec::task<void>
    {
        Frame frame {
            .tag = ProtocolTag::Ba,
            .target = target,
            .payload = encode_ba_envelope(instance_id_, msg)
        };
        bus_.push(std::move(frame));
        co_return;
    }

private:
    MessageBus& bus_;
    int instance_id_;
};

class CoinTransport {
public:
    CoinTransport(MessageBus& bus)
        : bus_(bus)
    {
    }

    auto broadcast(const Coin::Message& msg) -> exec::task<void>
    {
        Frame frame {
            .tag = ProtocolTag::Coin,
            .target = -1,
            .payload = encode_coin_message(msg)
        };
        bus_.push(std::move(frame));
        co_return;
    }

    auto unicast(int target, const Coin::Message& msg) -> exec::task<void>
    {
        Frame frame {
            .tag = ProtocolTag::Coin,
            .target = target,
            .payload = encode_coin_message(msg)
        };
        bus_.push(std::move(frame));
        co_return;
    }

private:
    MessageBus& bus_;
};

class HoneyBadgerTransport {
public:
    HoneyBadgerTransport(MessageBus& bus)
        : bus_(bus)
    {
    }

    auto broadcast(const HoneyBadger::DecShareMessage& msg) -> exec::task<void>
    {
        Frame frame {
            .tag = ProtocolTag::HbDecShare,
            .target = -1,
            .payload = encode_hb_decshare(msg)
        };
        bus_.push(std::move(frame));
        co_return;
    }

private:
    MessageBus& bus_;
};

} // namespace Honey::BFT::Network
