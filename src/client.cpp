#include "cryptography.hpp"
#include "secure_zero.h"
#include "udp_message_channel.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iostream>
#include <optional>
#include <random>
#include <stdexcept>
#include <string>

#include <arpa/inet.h>

namespace {

using Clock = std::chrono::steady_clock;
using InitAckPayload = Combined<ServerRandom, Nonce>;

struct Attempt {
    TotalPayload payload{};
    Secret secret{};

    ~Attempt() {
        secure_zero(&payload, sizeof(payload));
        secure_zero(secret.data(), secret.size());
    }
};

bool same_peer(const sockaddr_in& a, const sockaddr_in& b) {
    return a.sin_family == b.sin_family &&
           a.sin_addr.s_addr == b.sin_addr.s_addr &&
           a.sin_port == b.sin_port;
}

std::uint16_t parse_port(const char* value) {
    std::size_t length = 0;
    const unsigned long port = std::stoul(value, &length);
    if (value[length] != '\0' || port == 0 || port > 65535) {
        throw std::invalid_argument("Invalid server port");
    }
    return static_cast<std::uint16_t>(port);
}

template<typename Payload>
std::optional<Payload> wait_for(UdpMessageChannel& channel, MessageType type,
                                std::optional<std::uint32_t>& exchange_id,
                                const sockaddr_in& server, Clock::time_point deadline) {
    while (Clock::now() < deadline) {
        sockaddr_in sender{};
        auto message = channel.receive<Payload>(type, exchange_id, sender, std::cerr);
        if (!message) {
            continue;
        }
        if (Clock::now() >= deadline || !same_peer(sender, server)) {
            secure_zero(&*message, sizeof(*message));
            continue;
        }
        return message;
    }
    return std::nullopt;
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: client <server-ipv4> <port>\n";
        return 1;
    }

    try {
        sockaddr_in server{};
        server.sin_family = AF_INET;
        if (::inet_pton(AF_INET, argv[1], &server.sin_addr) != 1) {
            throw std::invalid_argument("Invalid server IPv4 address");
        }
        server.sin_port = htons(parse_port(argv[2]));

        UdpMessageChannel channel;
        channel.set_receive_timeout(std::chrono::milliseconds(200));
        std::random_device rng;
        Attempt attempt;
        attempt.payload.exchange_id = static_cast<std::uint32_t>(rng());
        for (auto& byte : attempt.payload.client_random) {
            byte = static_cast<std::uint8_t>(rng());
        }

        ClientRandom init{attempt.payload.client_random};
        const bool init_sent = channel.send(MessageType::INIT,
                                            attempt.payload.exchange_id,
                                            init, server, std::cerr);
        secure_zero(init.client_random.data(), init.client_random.size());
        if (!init_sent) {
            return 1;
        }

        const auto deadline = Clock::now() + std::chrono::seconds(5);
        std::optional<std::uint32_t> exchange_id = attempt.payload.exchange_id;
        auto init_ack = wait_for<InitAckPayload>(channel, MessageType::INIT_ACK,
                                                  exchange_id, server, deadline);
        if (!init_ack) {
            std::cerr << "INIT_ACK timeout\n";
            return 1;
        }
        attempt.payload.server_random = init_ack->server_random;
        attempt.payload.nonce = init_ack->nonce;
        secure_zero(&*init_ack, sizeof(*init_ack));
        attempt.secret = Calculate_secret(attempt.payload);

        HMAC confirm = Calculate_hmac(attempt.secret, MessageType::CONFIRM,
                                      attempt.payload);
        const bool confirm_sent = channel.send(MessageType::CONFIRM,
                                               attempt.payload.exchange_id,
                                               confirm, server, std::cerr);
        secure_zero(confirm.hmac.data(), confirm.hmac.size());
        if (!confirm_sent) {
            return 1;
        }

        auto ack = wait_for<HMAC>(channel, MessageType::CONFIRM_ACK,
                                  exchange_id, server, deadline);
        if (!ack) {
            std::cerr << "CONFIRM_ACK timeout\n";
            return 1;
        }
        HMAC expected = Calculate_hmac(attempt.secret, MessageType::CONFIRM_ACK,
                                       attempt.payload);
        const bool valid = *ack == expected;
        secure_zero(ack->hmac.data(), ack->hmac.size());
        secure_zero(expected.hmac.data(), expected.hmac.size());
        if (!valid) {
            std::cerr << "Invalid CONFIRM_ACK HMAC\n";
            return 1;
        }

        std::cout << "ok exchange=" << attempt.payload.exchange_id << std::endl;
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
