#include "../shared/protocol.h"

#include <algorithm>
#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
using namespace lab05;

struct ClientSession {
    int id;
    int sockfd;
    sockaddr_in addr{};
    bool active{true};
};

std::mutex clients_mutex;
std::vector<ClientSession> clients;
int next_client_id = 1;
std::atomic_bool server_running{true};

void handle_signal(int sig) {
    (void)sig;
    server_running = false;
}

std::optional<ClientSession> get_client_by_id(int id) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (const auto &client : clients) {
        if (client.id == id && client.active) {
            return client;
        }
    }
    return std::nullopt;
}

std::string format_client(const ClientSession &client) {
    char ip_buffer[INET_ADDRSTRLEN] = "unknown";
    inet_ntop(AF_INET, &client.addr.sin_addr, ip_buffer, sizeof(ip_buffer));
    std::ostringstream oss;
    oss << "#" << client.id << "\t" << ip_buffer << ":" << ntohs(client.addr.sin_port);
    return oss.str();
}

void send_string(int fd, PacketType type, const std::string &text) {
    send_packet(fd, type, text.c_str(), static_cast<std::uint32_t>(text.size() + 1));
}

void send_client_list(int fd) {
    std::ostringstream oss;
    {
        std::lock_guard<std::mutex> lock(clients_mutex);
        if (clients.empty()) {
            oss << "(no active clients)";
        } else {
            for (const auto &client : clients) {
                if (client.active) {
                    oss << format_client(client) << '\n';
                }
            }
        }
    }
    send_string(fd, PacketType::RESP_LIST, oss.str());
}

void send_current_time(int fd) {
    std::time_t now = std::time(nullptr);
    std::tm local_tm{};
#if defined(_WIN32)
    localtime_s(&local_tm, &now);
#else
    localtime_r(&now, &local_tm);
#endif
    char buffer[128];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &local_tm);
    send_string(fd, PacketType::RESP_TIME, buffer);
}

void send_host_name(int fd) {
    char host[128];
    if (::gethostname(host, sizeof(host)) != 0) {
        std::snprintf(host, sizeof(host), "lab05-server-%d", getpid());
    }
    host[sizeof(host) - 1] = '\0';
    send_string(fd, PacketType::RESP_NAME, host);
}

void send_error(int fd, const std::string &message) {
    send_string(fd, PacketType::RESP_ERROR, message);
}

void send_info(int fd, const std::string &message) {
    send_string(fd, PacketType::RESP_INFO, message);
}

bool forward_message(const ClientSession &sender, const std::vector<std::uint8_t> &payload) {
    if (payload.size() < sizeof(std::int32_t) + 1) {
        send_error(sender.sockfd, "Malformed forward payload");
        return false;
    }

    std::int32_t target_raw;
    std::memcpy(&target_raw, payload.data(), sizeof(target_raw));
    int target_id = ntohl(static_cast<std::uint32_t>(target_raw));
    std::string message(reinterpret_cast<const char *>(payload.data() + sizeof(target_raw)));

    auto receiver = get_client_by_id(target_id);
    if (!receiver) {
        send_error(sender.sockfd, "Target client not found");
        return false;
    }

    ForwardEnvelope env{};
    env.sender_id = htonl(sender.id);
    env.sender_ipv4 = sender.addr.sin_addr.s_addr;
    env.sender_port = sender.addr.sin_port;

    std::vector<std::uint8_t> buffer(sizeof(env) + message.size() + 1);
    std::memcpy(buffer.data(), &env, sizeof(env));
    std::memcpy(buffer.data() + sizeof(env), message.c_str(), message.size() + 1);

    if (!send_packet(receiver->sockfd, PacketType::INDICATION_MESSAGE, buffer)) {
        send_error(sender.sockfd, "Failed to deliver message");
        return false;
    }

    std::ostringstream oss;
    oss << "Message delivered to client #" << target_id;
    send_info(sender.sockfd, oss.str());
    return true;
}

void remove_client(int id) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (auto &client : clients) {
        if (client.id == id) {
            client.active = false;
            ::shutdown(client.sockfd, SHUT_RDWR);
            ::close(client.sockfd);
            break;
        }
    }
    clients.erase(
        std::remove_if(clients.begin(), clients.end(), [](const ClientSession &c) { return !c.active; }),
        clients.end());
}

void client_loop(ClientSession session) {
    char hello[160];
    char ip_buffer[INET_ADDRSTRLEN] = "unknown";
    inet_ntop(AF_INET, &session.addr.sin_addr, ip_buffer, sizeof(ip_buffer));
    std::snprintf(hello, sizeof(hello),
                  "Connected to Lab05 server. Assigned ID #%d (%s:%u)",
                  session.id, ip_buffer, ntohs(session.addr.sin_port));
    send_string(session.sockfd, PacketType::HELLO, hello);

    while (server_running && session.active) {
        PacketHeader header{};
        std::vector<std::uint8_t> payload;
        if (!recv_packet(session.sockfd, header, payload)) {
            break;
        }

        switch (static_cast<PacketType>(header.type)) {
            case PacketType::REQ_TIME:
                send_current_time(session.sockfd);
                break;
            case PacketType::REQ_NAME:
                send_host_name(session.sockfd);
                break;
            case PacketType::REQ_LIST:
                send_client_list(session.sockfd);
                break;
            case PacketType::REQ_FORWARD:
                forward_message(session, payload);
                break;
            default:
                send_error(session.sockfd, "Unknown request type");
                break;
        }
    }

    std::cout << "Client #" << session.id << " disconnected" << std::endl;
    remove_client(session.id);
}

}  // namespace

int main(int argc, char *argv[]) {
    std::signal(SIGINT, handle_signal);

    int port = lab05::DEFAULT_SERVER_PORT;
    if (argc >= 2) {
        port = std::stoi(argv[1]);
        if (port <= 0 || port > 65535) {
            std::cerr << "Invalid port: " << argv[1] << std::endl;
            return EXIT_FAILURE;
        }
    }

    int listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    int yes = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(static_cast<uint16_t>(port));

    if (::bind(listen_fd, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr)) < 0) {
        perror("bind");
        ::close(listen_fd);
        return EXIT_FAILURE;
    }

    if (::listen(listen_fd, 16) < 0) {
        perror("listen");
        ::close(listen_fd);
        return EXIT_FAILURE;
    }

    std::cout << "Lab05 server listening on port " << port << std::endl;

    while (server_running) {
        sockaddr_in client_addr{};
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = ::accept(listen_fd, reinterpret_cast<sockaddr *>(&client_addr), &addr_len);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            continue;
        }

        ClientSession session{};
        session.id = next_client_id++;
        session.sockfd = client_fd;
        session.addr = client_addr;

        {
            std::lock_guard<std::mutex> lock(clients_mutex);
            clients.push_back(session);
        }

        std::thread(client_loop, session).detach();
        std::cout << "Client #" << session.id << " connected" << std::endl;
    }

    std::cout << "Shutting down server..." << std::endl;
    ::close(listen_fd);

    std::lock_guard<std::mutex> lock(clients_mutex);
    for (auto &client : clients) {
        if (client.active) {
            ::shutdown(client.sockfd, SHUT_RDWR);
        }
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    return EXIT_SUCCESS;
}
