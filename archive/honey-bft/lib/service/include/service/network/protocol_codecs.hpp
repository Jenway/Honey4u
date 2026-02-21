#pragma once

#include "core/ba/messages.hpp"
#include "core/coin/messages.hpp"
#include "core/prbc/messages.hpp"
#include "core/rbc/messages.hpp"
#include "protocol/hb/concepts.hpp"
#include <cstddef>
#include <cstring>
#include <optional>
#include <set>
#include <span>
#include <vector>

namespace Honey::BFT::Network {

using Byte = std::byte;

inline void append_u32(std::vector<Byte>& buf, uint32_t v)
{
    buf.push_back(static_cast<Byte>((v >> 24) & 0xFF));
    buf.push_back(static_cast<Byte>((v >> 16) & 0xFF));
    buf.push_back(static_cast<Byte>((v >> 8) & 0xFF));
    buf.push_back(static_cast<Byte>(v & 0xFF));
}

inline bool read_u32(std::span<const Byte>& data, uint32_t& out)
{
    if (data.size() < 4)
        return false;
    out = (static_cast<uint32_t>(std::to_integer<uint8_t>(data[0])) << 24)
        | (static_cast<uint32_t>(std::to_integer<uint8_t>(data[1])) << 16)
        | (static_cast<uint32_t>(std::to_integer<uint8_t>(data[2])) << 8)
        | static_cast<uint32_t>(std::to_integer<uint8_t>(data[3]));
    data = data.subspan(4);
    return true;
}

inline void append_bytes(std::vector<Byte>& buf, std::span<const Byte> data)
{
    buf.insert(buf.end(), data.begin(), data.end());
}

inline bool read_bytes(std::span<const Byte>& data, size_t n, std::vector<Byte>& out)
{
    if (data.size() < n)
        return false;
    out.assign(data.begin(), data.begin() + n);
    data = data.subspan(n);
    return true;
}

inline std::vector<Byte> encode_rbc_message(const RBC::RBCMessage& msg)
{
    std::vector<Byte> buf;
    buf.reserve(1 + 4 + 4);
    buf.push_back(static_cast<Byte>(msg.type));
    append_u32(buf, static_cast<uint32_t>(msg.sender));
    append_u32(buf, static_cast<uint32_t>(msg.session_id));
    if (auto* p = std::get_if<RBC::ValPayload>(&msg.payload)) {
        RBC::serialize_payload(*p, buf);
    } else if (auto* p = std::get_if<RBC::EchoPayload>(&msg.payload)) {
        RBC::serialize_payload(*p, buf);
    } else if (auto* p = std::get_if<RBC::ReadyPayload>(&msg.payload)) {
        RBC::serialize_payload(*p, buf);
    }
    return buf;
}

inline std::optional<RBC::RBCMessage> decode_rbc_message(std::span<const Byte> data)
{
    if (data.size() < 9)
        return std::nullopt;
    auto type = static_cast<RBC::RBCMessage::Type>(std::to_integer<uint8_t>(data[0]));
    data = data.subspan(1);
    uint32_t sender = 0;
    uint32_t sid = 0;
    if (!read_u32(data, sender) || !read_u32(data, sid))
        return std::nullopt;
    RBC::RBCMessage msg {
        .type = type,
        .sender = static_cast<int>(sender),
        .session_id = static_cast<int>(sid),
        .payload = RBC::ReadyPayload {}
    };
    if (type == RBC::RBCMessage::Type::Val || type == RBC::RBCMessage::Type::Leader) {
        auto payload = RBC::deserialize_val(data);
        if (!payload)
            return std::nullopt;
        msg.payload = std::move(*payload);
    } else if (type == RBC::RBCMessage::Type::Echo) {
        auto payload = RBC::deserialize_echo(data);
        if (!payload)
            return std::nullopt;
        msg.payload = std::move(*payload);
    } else if (type == RBC::RBCMessage::Type::Ready) {
        auto payload = RBC::deserialize_ready(data);
        if (!payload)
            return std::nullopt;
        msg.payload = std::move(*payload);
    }
    return msg;
}

inline std::vector<Byte> encode_prbc_message(const PRBC::PRBCMessage& msg)
{
    std::vector<Byte> buf;
    buf.reserve(1 + 4 + 4);
    buf.push_back(static_cast<Byte>(msg.type));
    append_u32(buf, static_cast<uint32_t>(msg.sender));
    append_u32(buf, static_cast<uint32_t>(msg.session_id));
    if (auto* p = std::get_if<RBC::ValPayload>(&msg.payload)) {
        RBC::serialize_payload(*p, buf);
    } else if (auto* p = std::get_if<RBC::EchoPayload>(&msg.payload)) {
        RBC::serialize_payload(*p, buf);
    } else if (auto* p = std::get_if<PRBC::ReadyPayload>(&msg.payload)) {
        PRBC::serialize_payload(*p, buf);
    }
    return buf;
}

inline std::optional<PRBC::PRBCMessage> decode_prbc_message(std::span<const Byte> data)
{
    if (data.size() < 9)
        return std::nullopt;
    auto type = static_cast<PRBC::PRBCMessage::Type>(std::to_integer<uint8_t>(data[0]));
    data = data.subspan(1);
    uint32_t sender = 0;
    uint32_t sid = 0;
    if (!read_u32(data, sender) || !read_u32(data, sid))
        return std::nullopt;
    PRBC::PRBCMessage msg {
        .type = type,
        .sender = static_cast<int>(sender),
        .session_id = static_cast<int>(sid),
        .payload = PRBC::ReadyPayload {}
    };
    if (type == PRBC::PRBCMessage::Type::Val || type == PRBC::PRBCMessage::Type::Leader) {
        auto payload = PRBC::deserialize_val(data);
        if (!payload)
            return std::nullopt;
        msg.payload = std::move(*payload);
    } else if (type == PRBC::PRBCMessage::Type::Echo) {
        auto payload = PRBC::deserialize_echo(data);
        if (!payload)
            return std::nullopt;
        msg.payload = std::move(*payload);
    } else if (type == PRBC::PRBCMessage::Type::Ready) {
        auto payload = PRBC::deserialize_ready(data);
        if (!payload)
            return std::nullopt;
        msg.payload = std::move(*payload);
    }
    return msg;
}

inline std::vector<Byte> encode_ba_message(const BA::Message& msg)
{
    std::vector<Byte> buf;
    append_u32(buf, static_cast<uint32_t>(msg.sender));
    append_u32(buf, static_cast<uint32_t>(msg.session_id));
    if (auto* p = std::get_if<BA::ValPayload>(&msg.payload)) {
        buf.push_back(static_cast<Byte>(0));
        append_u32(buf, static_cast<uint32_t>(p->round));
        append_u32(buf, static_cast<uint32_t>(p->value));
    } else if (auto* p = std::get_if<BA::AuxPayload>(&msg.payload)) {
        buf.push_back(static_cast<Byte>(1));
        append_u32(buf, static_cast<uint32_t>(p->round));
        append_u32(buf, static_cast<uint32_t>(p->value));
    } else if (auto* p = std::get_if<BA::ConfPayload>(&msg.payload)) {
        buf.push_back(static_cast<Byte>(2));
        append_u32(buf, static_cast<uint32_t>(p->round));
        append_u32(buf, static_cast<uint32_t>(p->values.size()));
        for (auto v : p->values) {
            append_u32(buf, static_cast<uint32_t>(v));
        }
    }
    return buf;
}

inline std::optional<BA::Message> decode_ba_message(std::span<const Byte> data)
{
    uint32_t sender = 0;
    uint32_t sid = 0;
    if (!read_u32(data, sender) || !read_u32(data, sid))
        return std::nullopt;
    if (data.size() < 1)
        return std::nullopt;
    auto kind = std::to_integer<uint8_t>(data[0]);
    data = data.subspan(1);
    uint32_t round = 0;
    if (!read_u32(data, round))
        return std::nullopt;
    BA::Message msg {
        .sender = static_cast<int>(sender),
        .session_id = static_cast<int>(sid),
        .payload = BA::ValPayload { .round = static_cast<int>(round), .value = 0 }
    };
    if (kind == 0) {
        uint32_t value = 0;
        if (!read_u32(data, value))
            return std::nullopt;
        msg.payload = BA::ValPayload { .round = static_cast<int>(round), .value = static_cast<int>(value) };
    } else if (kind == 1) {
        uint32_t value = 0;
        if (!read_u32(data, value))
            return std::nullopt;
        msg.payload = BA::AuxPayload { .round = static_cast<int>(round), .value = static_cast<int>(value) };
    } else if (kind == 2) {
        uint32_t count = 0;
        if (!read_u32(data, count))
            return std::nullopt;
        std::set<int> values;
        for (uint32_t i = 0; i < count; ++i) {
            uint32_t v = 0;
            if (!read_u32(data, v))
                return std::nullopt;
            values.insert(static_cast<int>(v));
        }
        msg.payload = BA::ConfPayload { .round = static_cast<int>(round), .values = std::move(values) };
    } else {
        return std::nullopt;
    }
    return msg;
}

inline std::vector<Byte> encode_rbc_envelope(int instance_id, const RBC::RBCMessage& msg)
{
    std::vector<Byte> buf;
    append_u32(buf, static_cast<uint32_t>(instance_id));
    auto msg_bytes = encode_rbc_message(msg);
    append_bytes(buf, msg_bytes);
    return buf;
}

inline std::optional<std::pair<int, std::vector<Byte>>> decode_rbc_envelope(std::span<const Byte> data)
{
    uint32_t instance = 0;
    if (!read_u32(data, instance))
        return std::nullopt;
    std::vector<Byte> msg_bytes;
    if (!read_bytes(data, data.size(), msg_bytes))
        return std::nullopt;
    return std::make_pair(static_cast<int>(instance), std::move(msg_bytes));
}

inline std::vector<Byte> encode_prbc_envelope(int instance_id, const PRBC::PRBCMessage& msg)
{
    std::vector<Byte> buf;
    append_u32(buf, static_cast<uint32_t>(instance_id));
    auto msg_bytes = encode_prbc_message(msg);
    append_bytes(buf, msg_bytes);
    return buf;
}

inline std::optional<std::pair<int, std::vector<Byte>>> decode_prbc_envelope(std::span<const Byte> data)
{
    uint32_t instance = 0;
    if (!read_u32(data, instance))
        return std::nullopt;
    std::vector<Byte> msg_bytes;
    if (!read_bytes(data, data.size(), msg_bytes))
        return std::nullopt;
    return std::make_pair(static_cast<int>(instance), std::move(msg_bytes));
}

inline std::vector<Byte> encode_ba_envelope(int instance_id, const BA::Message& msg)
{
    std::vector<Byte> buf;
    append_u32(buf, static_cast<uint32_t>(instance_id));
    auto msg_bytes = encode_ba_message(msg);
    append_bytes(buf, msg_bytes);
    return buf;
}

inline std::optional<std::pair<int, std::vector<Byte>>> decode_ba_envelope(std::span<const Byte> data)
{
    uint32_t instance = 0;
    if (!read_u32(data, instance))
        return std::nullopt;
    std::vector<Byte> msg_bytes;
    if (!read_bytes(data, data.size(), msg_bytes))
        return std::nullopt;
    return std::make_pair(static_cast<int>(instance), std::move(msg_bytes));
}

inline std::vector<Byte> encode_coin_message(const Coin::Message& msg)
{
    std::vector<Byte> buf;
    append_u32(buf, static_cast<uint32_t>(msg.sender));
    append_u32(buf, static_cast<uint32_t>(msg.session_id));
    append_u32(buf, static_cast<uint32_t>(msg.payload.round));
    auto sig_bytes = std::span(reinterpret_cast<const Byte*>(msg.payload.sig.data()),
        sizeof(Coin::SignatureShare));
    append_bytes(buf, sig_bytes);
    return buf;
}

inline std::optional<Coin::Message> decode_coin_message(std::span<const Byte> data)
{
    uint32_t sender = 0;
    uint32_t sid = 0;
    uint32_t round = 0;
    if (!read_u32(data, sender) || !read_u32(data, sid) || !read_u32(data, round))
        return std::nullopt;
    if (data.size() < sizeof(Coin::SignatureShare))
        return std::nullopt;
    Coin::SignatureShare sig {};
    std::memcpy(sig.data(), data.data(), sizeof(Coin::SignatureShare));
    Coin::Message msg {
        .sender = static_cast<int>(sender),
        .session_id = static_cast<int>(sid),
        .payload = Coin::SharePayload { .round = static_cast<int>(round), .sig = sig }
    };
    return msg;
}

inline std::vector<Byte> encode_hb_decshare(const HoneyBadger::DecShareMessage& msg)
{
    std::vector<Byte> buf;
    append_u32(buf, static_cast<uint32_t>(msg.epoch));
    append_u32(buf, static_cast<uint32_t>(msg.ciphertext_index));
    append_u32(buf, static_cast<uint32_t>(msg.sender_id));
    append_u32(buf, static_cast<uint32_t>(msg.share_data.size()));
    append_bytes(buf, msg.share_data);
    return buf;
}

inline std::optional<HoneyBadger::DecShareMessage> decode_hb_decshare(std::span<const Byte> data)
{
    uint32_t epoch = 0;
    uint32_t idx = 0;
    uint32_t sender = 0;
    uint32_t size = 0;
    if (!read_u32(data, epoch) || !read_u32(data, idx) || !read_u32(data, sender) || !read_u32(data, size))
        return std::nullopt;
    std::vector<Byte> share;
    if (!read_bytes(data, size, share))
        return std::nullopt;
    return HoneyBadger::DecShareMessage {
        .epoch = static_cast<int>(epoch),
        .ciphertext_index = static_cast<int>(idx),
        .sender_id = static_cast<int>(sender),
        .share_data = std::move(share)
    };
}

} // namespace Honey::BFT::Network
