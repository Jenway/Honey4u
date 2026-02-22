#pragma once

#include <cstddef>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

// 假设我们使用 zpp_bits (推荐) 或 cereal
// #include <zpp_bits.h>

namespace Honey::BFT::Network {

struct BinaryCodec {
    /**
     * @brief 将任意强类型 Msg 序列化为二进制
     * 注意：推荐使用 zpp_bits，下面是伪代码示意
     */
    template <typename Msg>
    static std::vector<std::byte> encode(const Msg& msg)
    {
        // [示例] 如果你有 zpp_bits:
        // auto [data, out] = zpp::bits::data_out();
        // out(msg).or_throw();
        // return data;

        // [临时方案] 仅仅为了让代码能跑，假设 Msg 有 serialize() 方法
        // 在实际项目中，请替换为真实的二进制库调用
        return msg.serialize();
    }

    /**
     * @brief 将二进制反序列化为 Msg
     */
    template <typename Msg>
    static std::optional<Msg> decode(const std::vector<std::byte>& data)
    {
        try {
            Msg msg;
            // [示例] 如果你有 zpp_bits:
            // auto in = zpp::bits::in(data);
            // in(msg).or_throw();

            // [临时方案]
            if (msg.deserialize(data)) {
                return msg;
            }
            return std::nullopt;
        } catch (...) {
            return std::nullopt;
        }
    }
};

} // namespace Honey::BFT::Network
