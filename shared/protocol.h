#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace lab05 {

inline constexpr std::uint16_t PROTOCOL_MAGIC = 0x4C35;  // 'L5'
inline constexpr std::size_t MAX_TEXT_PAYLOAD = 1024;
inline constexpr std::size_t MAX_MESSAGE_LENGTH = 512;
inline constexpr std::uint16_t DEFAULT_SERVER_PORT = 2930;

enum class PacketType : std::uint16_t {
    HELLO = 1,
    REQ_TIME = 10,
    REQ_NAME = 11,
    REQ_LIST = 12,
    REQ_FORWARD = 13,
    RESP_INFO = 20,
    RESP_TIME = 21,
    RESP_NAME = 22,
    RESP_LIST = 23,
    RESP_ERROR = 24,
    INDICATION_MESSAGE = 30
};

#pragma pack(push, 1)
struct PacketHeader {
    std::uint16_t magic;
    std::uint16_t type;
    std::uint32_t length;
};

struct ForwardEnvelope {
    std::int32_t sender_id;
    std::uint32_t sender_ipv4;
    std::uint16_t sender_port;
    std::uint16_t reserved;
};
#pragma pack(pop)

bool send_packet(int fd, PacketType type, const void *payload, std::uint32_t length);
inline bool send_packet(int fd, PacketType type, const std::vector<std::uint8_t> &payload) {
    return send_packet(fd, type, payload.data(), static_cast<std::uint32_t>(payload.size()));
}

bool recv_packet(int fd, PacketHeader &header, std::vector<std::uint8_t> &payload);
std::string packet_type_name(std::uint16_t type);

}  // namespace lab05
