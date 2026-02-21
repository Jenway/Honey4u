#pragma once

#include "service/network/message_bus.hpp"
#include <nlohmann/json.hpp>
#include <vector>

namespace Honey::BFT::Network {

using json = nlohmann::json;

<<<<<<< Updated upstream
/**
 * @brief 协议编解码：Frame 的序列化/反序列化
 *
 * 职责：将 Frame 序列化成网络字节流，或从网络字节流反序列化回 Frame
 * 注意：payload 应该已经由 crypto 层序列化好，这里只负责编码整个 Frame
 */
class ProtocolCodec {
public:
    /**
     * @brief 序列化 Frame 为 JSON 字节流
     * @param frame 消息帧
     * @return 序列化后的字节数据
     */
    == == == = class ProtocolCodec {
    public:
>>>>>>> Stashed changes
        static std::vector<std::byte> encode(const Frame& frame)
        {
            json j {
                { "tag", static_cast<int>(frame.tag) },
                { "target", frame.target },
                { "payload", hex_encode(frame.payload) }
            };

            std::string json_str = j.dump();
            std::vector<std::byte> result;
            for (char c : json_str) {
                result.push_back(static_cast<std::byte>(c));
            }
            return result;
        }

<<<<<<< Updated upstream
        /**
         * @brief 反序列化 JSON 字节流为 Frame
         * @param data 字节数据
         * @param sender_id 发送方节点 ID
         * @return 反序列化后的 Frame
         */
        == == == =
>>>>>>> Stashed changes
            static std::optional<Frame> decode(const std::vector<std::byte>& data, int sender_id)
        {
            try {
                std::string json_str;
                for (auto byte : data) {
                    json_str += static_cast<char>(byte);
                }

                auto j = json::parse(json_str);
                return Frame {
                    .tag = static_cast<ProtocolTag>(j["tag"].get<int>()),
                    .sender_id = sender_id,
                    .target = j.value("target", -1),
                    .payload = hex_decode(j["payload"].get<std::string>()),
                    .direction = FrameDirection::Inbound
                };
            } catch (const std::exception&) {
                return std::nullopt;
            }
        }

    private:
<<<<<<< Updated upstream
        /**
         * @brief 十六进制编码（只用于 payload 在 JSON 中的表示）
         */
        == == == =
>>>>>>> Stashed changes
            static std::string hex_encode(const std::vector<std::byte>& data)
        {
            static constexpr char hex_chars[] = "0123456789abcdef";
            std::string result;
            result.reserve(data.size() * 2);
            for (auto byte : data) {
                auto b = static_cast<unsigned char>(byte);
                result += hex_chars[b >> 4];
                result += hex_chars[b & 0x0f];
            }
            return result;
        }

<<<<<<< Updated upstream
        /**
         * @brief 十六进制解码
         */
        == == == =
>>>>>>> Stashed changes
            static std::vector<std::byte> hex_decode(const std::string& hex)
        {
            std::vector<std::byte> result;
            result.reserve(hex.size() / 2);
            for (size_t i = 0; i < hex.size(); i += 2) {
                unsigned char byte = 0;
                for (int j = 0; j < 2; j++) {
                    char c = hex[i + j];
                    byte = byte * 16 + (c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10);
                }
                result.push_back(static_cast<std::byte>(byte));
            }
            return result;
        }
    };

} // namespace Honey::BFT::Network
