#include "../shared/protocol.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <deque>
#include <iostream>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace {
using namespace lab05;

std::atomic_bool process_running{true};
std::atomic_bool client_connected{false};
int client_socket = -1;
std::atomic_bool receiver_alive{false};
std::thread receiver_thread;

std::mutex queue_mutex;
std::deque<std::string> message_queue;

void push_message(const std::string &tag, const std::string &body) {
    std::lock_guard<std::mutex> lock(queue_mutex);
    message_queue.emplace_back(tag + " " + body);
}

void drain_messages() {
    std::lock_guard<std::mutex> lock(queue_mutex);
    while (!message_queue.empty()) {
        std::cout << message_queue.front() << std::endl;
        message_queue.pop_front();
    }
}

void handle_signal(int) {
    process_running = false;
}

void cleanup_connection() {
    if (client_socket >= 0) {
        ::shutdown(client_socket, SHUT_RDWR);
        ::close(client_socket);
        client_socket = -1;
    }
    client_connected = false;
}

std::string payload_to_text(const std::vector<std::uint8_t> &payload) {
    if (payload.empty()) {
        return {};
    }
    std::size_t len = strnlen(reinterpret_cast<const char *>(payload.data()), payload.size());
    return std::string(reinterpret_cast<const char *>(payload.data()), len);
}

void receiver_loop() {
    receiver_alive = true;
    while (client_connected) {
        PacketHeader header{};
        std::vector<std::uint8_t> payload;
        if (!recv_packet(client_socket, header, payload)) {
            push_message("[ERROR]", "Connection closed by server");
            cleanup_connection();
            break;
        }

        switch (static_cast<PacketType>(header.type)) {
            case PacketType::HELLO:
                push_message("[SERVER]", payload_to_text(payload));
                break;
            case PacketType::RESP_TIME:
                push_message("[TIME]", payload_to_text(payload));
                break;
            case PacketType::RESP_NAME:
                push_message("[NAME]", payload_to_text(payload));
                break;
            case PacketType::RESP_LIST:
                push_message("[CLIENTS]", payload_to_text(payload));
                break;
            case PacketType::RESP_INFO:
                push_message("[INFO]", payload_to_text(payload));
                break;
            case PacketType::RESP_ERROR:
                push_message("[ERROR]", payload_to_text(payload));
                break;
            case PacketType::INDICATION_MESSAGE: {
                if (payload.size() < sizeof(ForwardEnvelope)) {
                    push_message("[ERROR]", "Malformed indication packet");
                    break;
                }
                ForwardEnvelope envelope{};
                std::memcpy(&envelope, payload.data(), sizeof(envelope));
                int sender_id = ntohl(static_cast<std::uint32_t>(envelope.sender_id));
                char ip_buffer[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &envelope.sender_ipv4, ip_buffer, sizeof(ip_buffer));
                unsigned short sender_port = ntohs(envelope.sender_port);
                std::string message(reinterpret_cast<const char *>(payload.data() + sizeof(envelope)));
                push_message("[MESSAGE]",
                             "From #" + std::to_string(sender_id) + " (" + ip_buffer + ":" +
                                 std::to_string(sender_port) + "): " + message);
                break;
            }
            default:
                push_message("[INFO]", "Unknown packet type received");
                break;
        }
    }
    receiver_alive = false;
}

bool wait_for_line(std::string &line) {
    while (process_running) {
        drain_messages();
    pollfd pfd{};
    pfd.fd = STDIN_FILENO;
    pfd.events = POLLIN;
        int ret = ::poll(&pfd, 1, 200);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (ret == 0) {
            continue;
        }
        if (pfd.revents & POLLIN) {
            if (!std::getline(std::cin, line)) {
                return false;
            }
            return true;
        }
    }
    return false;
}

bool prompt_line(const std::string &label, std::string &out) {
    std::cout << label;
    std::cout.flush();
    if (!wait_for_line(out)) {
        return false;
    }
    return true;
}

std::string trim(const std::string &text) {
    const char *whitespace = " \t\r\n";
    auto start = text.find_first_not_of(whitespace);
    if (start == std::string::npos) {
        return "";
    }
    auto end = text.find_last_not_of(whitespace);
    return text.substr(start, end - start + 1);
}

bool start_receiver_thread() {
    receiver_thread = std::thread(receiver_loop);
    return true;
}

bool connect_to_server() {
    if (client_connected) {
        push_message("[INFO]", "Already connected");
        return false;
    }

    std::string host;
    std::string port_text;
    if (!prompt_line("服务器IP或主机名: ", host)) {
        return false;
    }
    if (!prompt_line("端口: ", port_text)) {
        return false;
    }

    host = trim(host);
    port_text = trim(port_text);
    int port = 0;
    try {
        port = std::stoi(port_text);
    } catch (const std::exception &) {
        push_message("[ERROR]", "Invalid port number");
        return false;
    }
    if (port <= 0 || port > 65535) {
        push_message("[ERROR]", "Invalid port number");
        return false;
    }

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo *result = nullptr;
    int err = ::getaddrinfo(host.c_str(), port_text.c_str(), &hints, &result);
    if (err != 0) {
        push_message("[ERROR]", std::string("Address resolution failed: ") + gai_strerror(err));
        return false;
    }

    int sockfd = -1;
    for (addrinfo *rp = result; rp != nullptr; rp = rp->ai_next) {
        sockfd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sockfd < 0) {
            continue;
        }
        if (::connect(sockfd, rp->ai_addr, rp->ai_addrlen) == 0) {
            client_socket = sockfd;
            client_connected = true;
            break;
        }
        ::close(sockfd);
        sockfd = -1;
    }
    ::freeaddrinfo(result);

    if (!client_connected) {
        push_message("[ERROR]", "Unable to connect to server");
        return false;
    }

    start_receiver_thread();
    push_message("[INFO]", "连接成功");
    return true;
}

void disconnect_from_server() {
    if (!client_connected) {
        push_message("[INFO]", "尚未连接");
        return;
    }

    cleanup_connection();
    if (receiver_thread.joinable()) {
        receiver_thread.join();
    }
    receiver_alive = false;
    push_message("[INFO]", "连接已断开");
}

bool send_simple_request(PacketType type) {
    if (!client_connected) {
        push_message("[ERROR]", "请先连接服务器");
        return false;
    }
    if (!send_packet(client_socket, type, nullptr, 0)) {
        push_message("[ERROR]", "发送请求失败");
        return false;
    }
    return true;
}

void send_chat_message() {
    if (!client_connected) {
        push_message("[ERROR]", "请先连接服务器");
        return;
    }

    std::string id_text;
    if (!prompt_line("输入目标客户端编号: ", id_text)) {
        return;
    }
    int target_id = 0;
    try {
        target_id = std::stoi(trim(id_text));
    } catch (const std::exception &) {
        target_id = 0;
    }
    if (target_id <= 0) {
        push_message("[ERROR]", "编号无效");
        return;
    }

    std::string message;
    if (!prompt_line("输入要发送的内容: ", message)) {
        return;
    }
    message = trim(message);
    if (message.empty()) {
        push_message("[ERROR]", "消息不能为空");
        return;
    }

    std::vector<std::uint8_t> payload(sizeof(std::int32_t) + message.size() + 1);
    std::int32_t net_target = htonl(target_id);
    std::memcpy(payload.data(), &net_target, sizeof(net_target));
    std::memcpy(payload.data() + sizeof(net_target), message.c_str(), message.size() + 1);

    if (!send_packet(client_socket, PacketType::REQ_FORWARD, payload)) {
        push_message("[ERROR]", "发送消息失败");
    }
}

void print_menu() {
    std::cout << "\n===== Lab05 客户端菜单 =====\n";
    std::cout << "1. 连接服务器\n";
    std::cout << "2. 断开连接\n";
    std::cout << "3. 获取时间\n";
    std::cout << "4. 获取服务器主机名\n";
    std::cout << "5. 获取活动客户端列表\n";
    std::cout << "6. 向客户端发送消息\n";
    std::cout << "7. 退出\n";
    std::cout << "请选择操作: " << std::flush;
}

}  // namespace

int main() {
    std::signal(SIGINT, handle_signal);

    while (process_running) {
        print_menu();
        std::string input;
        if (!wait_for_line(input)) {
            break;
        }
        input = trim(input);
        int choice = 0;
        if (!input.empty()) {
            try {
                choice = std::stoi(input);
            } catch (const std::exception &) {
                choice = 0;
            }
        }
        switch (choice) {
            case 1:
                connect_to_server();
                break;
            case 2:
                disconnect_from_server();
                break;
            case 3:
                send_simple_request(PacketType::REQ_TIME);
                break;
            case 4:
                send_simple_request(PacketType::REQ_NAME);
                break;
            case 5:
                send_simple_request(PacketType::REQ_LIST);
                break;
            case 6:
                send_chat_message();
                break;
            case 7:
                process_running = false;
                break;
            default:
                push_message("[ERROR]", "无效的选项");
                break;
        }
        drain_messages();
    }

    disconnect_from_server();
    if (receiver_thread.joinable()) {
        receiver_thread.join();
    }
    drain_messages();
    return 0;
}
