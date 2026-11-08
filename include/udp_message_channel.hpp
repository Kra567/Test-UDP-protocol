#pragma once

#include <array>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <string>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "messages.hpp"
#include "secure_zero.h"
#include "validation.hpp"

// Один экземпляр принимает пакеты последовательно: peek и consume
// относятся к одной и той же очереди датаграмм.
class UdpMessageChannel {
public:
    UdpMessageChannel() {
        fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (fd_ == -1) {
            throw std::runtime_error(std::string("socket: ") + std::strerror(errno));
        }
    }

    ~UdpMessageChannel() {
        if (fd_ != -1) {
            ::close(fd_);
        }
    }

    UdpMessageChannel(const UdpMessageChannel&) = delete;
    UdpMessageChannel& operator=(const UdpMessageChannel&) = delete;

    std::uint16_t bind(const sockaddr_in& address) {
        if (::bind(fd_, reinterpret_cast<const sockaddr*>(&address),
                   sizeof(address)) == -1) {
            throw std::runtime_error(std::string("bind: ") + std::strerror(errno));
        }

        sockaddr_in bound_address{};
        socklen_t length = sizeof(bound_address);
        if (::getsockname(fd_, reinterpret_cast<sockaddr*>(&bound_address),
                          &length) == -1) {
            throw std::runtime_error(std::string("getsockname: ") + std::strerror(errno));
        }
        return ntohs(bound_address.sin_port);
    }

    void set_receive_timeout(std::chrono::milliseconds duration) {
        timeval timeout{};
        timeout.tv_sec = duration.count() / 1000;
        timeout.tv_usec = (duration.count() % 1000) * 1000;
        if (::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO,
                         &timeout, sizeof(timeout)) == -1) {
            throw std::runtime_error(std::string("setsockopt: ") + std::strerror(errno));
        }
    }

    template<typename Payload>
    bool send(MessageType type, std::uint32_t exchange_id,
              const Payload& payload, const sockaddr_in& destination,
              std::ostream& log) {
        constexpr std::size_t header_size = ByteSerializable<Header>::byte_size();
        constexpr std::size_t payload_size = ByteSerializable<Payload>::byte_size();
        static_assert(payload_size <= 2048, "Payload exceeds protocol limit");

        std::array<std::uint8_t, header_size + payload_size> buffer{};
        auto* ptr = buffer.data();
        Header header{};
        header.type = static_cast<std::uint8_t>(type);
        header.exchange_id = exchange_id;
        ByteSerializable<Header>::serialize(header, ptr);
        ByteSerializable<Payload>::serialize(payload, ptr);

        const ssize_t sent = ::sendto(
            fd_, buffer.data(), buffer.size(), 0,
            reinterpret_cast<const sockaddr*>(&destination), sizeof(destination));
        secure_zero(buffer.data(), buffer.size());
        if (sent < 0) {
            log << "sendto: " << std::strerror(errno) << '\n';
            return false;
        }
        if (static_cast<std::size_t>(sent) != buffer.size()) {
            log << "Incomplete UDP send\n";
            return false;
        }
        return true;
    }

    template<typename Payload>
    std::optional<Payload> receive(MessageType expected_type,
                                   std::optional<std::uint32_t>& exchange_id,
                                   sockaddr_in& sender, std::ostream& log) {
        constexpr std::size_t header_size = ByteSerializable<Header>::byte_size();
        constexpr std::size_t payload_size = ByteSerializable<Payload>::byte_size();
        constexpr std::size_t packet_size = header_size + payload_size;
        static_assert(payload_size <= 2048, "Payload exceeds protocol limit");

        std::array<std::uint8_t, header_size> header_bytes{};
        iovec part{header_bytes.data(), header_bytes.size()};
        msghdr peek{};
        peek.msg_iov = &part;
        peek.msg_iovlen = 1;

        // Linux: MSG_TRUNC сообщает полную длину датаграммы даже при коротком iovec.
        const ssize_t length = ::recvmsg(fd_, &peek,
                                         MSG_PEEK | MSG_TRUNC);
        if (length < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                return std::nullopt;
            }
            log << "recvmsg: " << std::strerror(errno) << '\n';
            return std::nullopt;
        }

        if (static_cast<std::size_t>(length) < header_size) {
            log << "Truncated header\n";
            discard(log);
            return std::nullopt;
        }

        auto* header_ptr = header_bytes.data();
        const Header header = ByteSerializable<Header>::deserialize(header_ptr);
        Header expected{};
        expected.type = static_cast<std::uint8_t>(expected_type);
        expected.exchange_id = exchange_id.value_or(header.exchange_id);

        if (!compare(header, expected, log) ||
            static_cast<std::size_t>(length) != packet_size) {
            if (static_cast<std::size_t>(length) != packet_size) {
                log << "Invalid packet size: " << length
                    << ", expected " << packet_size << '\n';
            }
            discard(log);
            return std::nullopt;
        }

        // +1 позволяет обнаружить изменение размера между peek и consume.
        std::array<std::uint8_t, packet_size + 1> buffer{};
        sockaddr_in actual_sender{};
        socklen_t sender_length = sizeof(actual_sender);
        const ssize_t received = ::recvfrom(
            fd_, buffer.data(), buffer.size(), 0,
            reinterpret_cast<sockaddr*>(&actual_sender), &sender_length);
        if (received < 0) {
            log << "recvfrom: " << std::strerror(errno) << '\n';
            return std::nullopt;
        }
        if (static_cast<std::size_t>(received) != packet_size) {
            log << "Invalid packet size: " << received
                << ", expected " << packet_size << '\n';
            secure_zero(buffer.data(), buffer.size());
            return std::nullopt;
        }

        auto* ptr = buffer.data();
        const Header actual_header = ByteSerializable<Header>::deserialize(ptr);
        Header actual_expected{};
        actual_expected.type = static_cast<std::uint8_t>(expected_type);
        actual_expected.exchange_id = exchange_id.value_or(actual_header.exchange_id);
        if (!compare(actual_header, actual_expected, log)) {
            secure_zero(buffer.data(), buffer.size());
            return std::nullopt;
        }

        Payload payload = ByteSerializable<Payload>::deserialize(ptr);
        secure_zero(buffer.data(), buffer.size());
        exchange_id = actual_header.exchange_id;
        sender = actual_sender;
        return payload;
    }

private:
    void discard(std::ostream& log) {
        std::uint8_t byte = 0;
        if (::recvfrom(fd_, &byte, sizeof(byte), 0,
                       nullptr, nullptr) < 0) {
            log << "recvfrom: " << std::strerror(errno) << '\n';
        }
    }

    int fd_ = -1;
};
