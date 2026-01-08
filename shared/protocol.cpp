#include "protocol.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <stdexcept>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

namespace lab05 {
namespace {

ssize_t send_all(int fd, const void *buffer, std::size_t length) {
    const std::uint8_t *data = static_cast<const std::uint8_t *>(buffer);
    std::size_t total = 0;
    while (total < length) {
        ssize_t sent = ::send(fd, data + total, length - total, 0);
        if (sent < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (sent == 0) {
            break;
        }
        total += static_cast<std::size_t>(sent);
    }
    return static_cast<ssize_t>(total);
}

ssize_t recv_all(int fd, void *buffer, std::size_t length) {
    std::uint8_t *data = static_cast<std::uint8_t *>(buffer);
    std::size_t total = 0;
    while (total < length) {
        ssize_t received = ::recv(fd, data + total, length - total, 0);
        if (received < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (received == 0) {
            return 0;
        }
        total += static_cast<std::size_t>(received);
    }
    return static_cast<ssize_t>(total);
}

}  // namespace

bool send_packet(int fd, PacketType type, const void *payload, std::uint32_t length) {
    PacketHeader header{};
    header.magic = htons(PROTOCOL_MAGIC);
    header.type = htons(static_cast<std::uint16_t>(type));
    header.length = htonl(length);

    if (send_all(fd, &header, sizeof(header)) != static_cast<ssize_t>(sizeof(header))) {
        return false;
    }

    if (length > 0 && payload != nullptr) {
        if (send_all(fd, payload, length) != static_cast<ssize_t>(length)) {
            return false;
        }
    }

    return true;
}

bool recv_packet(int fd, PacketHeader &header, std::vector<std::uint8_t> &payload) {
    PacketHeader network_header{};
    ssize_t bytes = recv_all(fd, &network_header, sizeof(network_header));
    if (bytes <= 0) {
        return false;
    }
    if (static_cast<std::size_t>(bytes) != sizeof(network_header)) {
        errno = EPROTO;
        return false;
    }

    header.magic = ntohs(network_header.magic);
    header.type = ntohs(network_header.type);
    header.length = ntohl(network_header.length);

    if (header.magic != PROTOCOL_MAGIC) {
        errno = EPROTO;
        return false;
    }

    if (header.length > 10 * 1024 * 1024) {
        errno = EMSGSIZE;
        return false;
    }

    payload.clear();
    if (header.length > 0) {
        payload.resize(header.length);
        ssize_t payload_bytes = recv_all(fd, payload.data(), payload.size());
        if (payload_bytes <= 0) {
            payload.clear();
            return false;
        }
        if (static_cast<std::uint32_t>(payload_bytes) != header.length) {
            errno = EPROTO;
            payload.clear();
            return false;
        }
    }

    return true;
}

std::string packet_type_name(std::uint16_t type) {
    switch (static_cast<PacketType>(type)) {
        case PacketType::HELLO:
            return "HELLO";
        case PacketType::REQ_TIME:
            return "REQ_TIME";
        case PacketType::REQ_NAME:
            return "REQ_NAME";
        case PacketType::REQ_LIST:
            return "REQ_LIST";
        case PacketType::REQ_FORWARD:
            return "REQ_FORWARD";
        case PacketType::RESP_INFO:
            return "RESP_INFO";
        case PacketType::RESP_TIME:
            return "RESP_TIME";
        case PacketType::RESP_NAME:
            return "RESP_NAME";
        case PacketType::RESP_LIST:
            return "RESP_LIST";
        case PacketType::RESP_ERROR:
            return "RESP_ERROR";
        case PacketType::INDICATION_MESSAGE:
            return "INDICATION_MESSAGE";
        default:
            return "UNKNOWN";
    }
}

}  // namespace lab05
