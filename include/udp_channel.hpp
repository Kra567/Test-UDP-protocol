#pragma once

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <limits>
#include <optional>
#include <string>

#include "secure_bytes.hpp"

#include <arpa/inet.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

enum class MessageType : std::uint8_t {
    INIT = 1,
    INIT_ACK = 2,
    CONFIRM = 3,
    CONFIRM_ACK = 4
};

inline constexpr std::uint32_t MAGIC = 0x4B455931;

struct UdpAddress {
    std::string ip;
    std::uint16_t port;

    std::optional<sockaddr_in> to_sockaddr() const {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        if (::inet_pton(AF_INET, ip.c_str(), &address.sin_addr) != 1) {
            return std::nullopt;
        }
        return address;
    }
};

class UdpChannel {
public:
    UdpChannel() : fd_(::socket(AF_INET, SOCK_DGRAM, 0)) {}

    ~UdpChannel() {
        if (fd_ != -1) {
            ::close(fd_);
        }
    }

    UdpChannel(const UdpChannel&) = delete;
    UdpChannel& operator=(const UdpChannel&) = delete;

    std::optional<UdpAddress> bind(const UdpAddress& address) {
        auto endpoint = address.to_sockaddr();
        if (fd_ == -1 || !endpoint) {
            return std::nullopt;
        }

        if (::bind(fd_, reinterpret_cast<const sockaddr*>(&*endpoint),
                   sizeof(*endpoint)) == -1) {
            return std::nullopt;
        }

        sockaddr_in bound{};
        socklen_t length = sizeof(bound);
        if (::getsockname(fd_, reinterpret_cast<sockaddr*>(&bound), &length) == -1) {
            ::close(fd_);
            fd_ = -1;
            return std::nullopt;
        }
        return UdpAddress{address.ip, ntohs(bound.sin_port)};
    }

    template<std::size_t N>
    bool send(MessageType type, std::uint32_t exchange_id,
              const std::array<std::uint8_t, N>& payload,
              const UdpAddress& destination) {
        static_assert(N <= 2048, "UDP payload exceeds 2048 bytes");

        auto endpoint = destination.to_sockaddr();
        if (fd_ == -1 || !endpoint) {
            return false;
        }

        SecureBytes<12 + N> packet{};
        packet[0] = static_cast<std::uint8_t>(MAGIC >> 24);
        packet[1] = static_cast<std::uint8_t>(MAGIC >> 16);
        packet[2] = static_cast<std::uint8_t>(MAGIC >> 8);
        packet[3] = static_cast<std::uint8_t>(MAGIC);
        packet[4] = 1;
        packet[5] = static_cast<std::uint8_t>(type);
        // flags и reserved уже равны нулю.
        packet[8] = static_cast<std::uint8_t>(exchange_id >> 24);
        packet[9] = static_cast<std::uint8_t>(exchange_id >> 16);
        packet[10] = static_cast<std::uint8_t>(exchange_id >> 8);
        packet[11] = static_cast<std::uint8_t>(exchange_id);
        std::copy(payload.begin(), payload.end(), packet.begin() + 12);

        return ::sendto(fd_, packet.data(), packet.size(), 0,
                        reinterpret_cast<const sockaddr*>(&*endpoint),
                        sizeof(*endpoint)) == static_cast<ssize_t>(packet.size());
    }

    template<std::size_t N>
    std::optional<SecureBytes<N>> receive(
        const MessageType& expected_type,
        std::optional<std::uint32_t>& exchange_id,
        std::optional<UdpAddress>& sender,
        std::optional<std::chrono::milliseconds> max_wait = std::nullopt
    ) {
        static_assert(N <= 2048, "UDP payload exceeds 2048 bytes");

        if (max_wait) {
            const auto deadline = std::chrono::steady_clock::now() + *max_wait;
            for (;;) {
                const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
                    deadline - std::chrono::steady_clock::now());
                const auto milliseconds = std::clamp<std::chrono::milliseconds::rep>(
                    remaining.count(), 0, std::numeric_limits<int>::max());
                pollfd ready{fd_, POLLIN, 0};
                const int result = ::poll(&ready, 1, static_cast<int>(milliseconds));
                if (result > 0) {
                    break;
                }
                if (result == 0) {
                    return std::nullopt;
                }
                if (errno != EINTR) {
                    std::cerr << "poll: " << std::strerror(errno) << '\n';
                    return std::nullopt;
                }
            }
        }

        // Лишний байт позволяет обнаружить датаграмму длиннее ожидаемой.
        SecureBytes<12 + N + 1> packet{};
        sockaddr_in actual_sender{};
        socklen_t sender_length = sizeof(actual_sender);
        const ssize_t received = ::recvfrom(
            fd_, packet.data(), packet.size(), 0,
            reinterpret_cast<sockaddr*>(&actual_sender), &sender_length);
        if (received == -1) {
            std::cerr << "recvfrom: " << std::strerror(errno) << '\n';
            return std::nullopt;
        }
        if (received != static_cast<ssize_t>(12 + N)) {
            std::cerr << "wrong value at LENGTH: " << received
                      << " (expected " << 12 + N << ")\n";
            return std::nullopt;
        }
        if (sender_length != sizeof(actual_sender)) {
            std::cerr << "wrong value at ADDRESS_LENGTH: " << sender_length
                      << " (expected " << sizeof(actual_sender) << ")\n";
            return std::nullopt;
        }

        auto check = [](const char* field, std::uint32_t real,
                        std::uint32_t expected) {
            if (real != expected) {
                std::cerr << "wrong value at " << field << ": " << real
                          << " (expected " << expected << ")\n";
                return false;
            }
            return true;
        };
        const std::uint32_t magic =
            (std::uint32_t{packet[0]} << 24) |
            (std::uint32_t{packet[1]} << 16) |
            (std::uint32_t{packet[2]} << 8) |
            packet[3];
        const std::uint32_t actual_id =
            (std::uint32_t{packet[8]} << 24) |
            (std::uint32_t{packet[9]} << 16) |
            (std::uint32_t{packet[10]} << 8) |
            packet[11];

        if (!check("MAGIC", magic, MAGIC) ||
            !check("VERSION", packet[4], 1) ||
            !check("TYPE", packet[5], static_cast<std::uint8_t>(expected_type)) ||
            !check("FLAGS", packet[6], 0) ||
            !check("RESERVED", packet[7], 0) ||
            (exchange_id && !check("EXCHANGE_ID", actual_id, *exchange_id))) {
            return std::nullopt;
        }

        char ip[INET_ADDRSTRLEN]{};
        if (::inet_ntop(AF_INET, &actual_sender.sin_addr, ip, sizeof(ip)) == nullptr) {
            std::cerr << "inet_ntop: " << std::strerror(errno) << '\n';
            return std::nullopt;
        }
        const UdpAddress actual_address{ip, ntohs(actual_sender.sin_port)};
        if (sender) {
            const auto expected = sender->to_sockaddr();
            if (!expected ||
                actual_sender.sin_addr.s_addr != expected->sin_addr.s_addr ||
                actual_sender.sin_port != expected->sin_port) {
                std::cerr << "wrong value at SENDER: " << actual_address.ip
                          << ':' << actual_address.port << " (expected "
                          << sender->ip << ':' << sender->port << ")\n";
                return std::nullopt;
            }
        }

        SecureBytes<N> payload{};
        std::copy_n(packet.begin() + 12, N, payload.begin());
        if (!sender) {
            sender = actual_address;
        }
        if (!exchange_id) {
            exchange_id = actual_id;
        }
        return payload;
    }

private:
    int fd_ = -1;
};
