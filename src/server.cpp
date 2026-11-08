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
#include <unordered_set>

#include <arpa/inet.h>

namespace {

using Clock = std::chrono::steady_clock;
using InitAckPayload = Combined<ServerRandom, Nonce>;

struct Session {
    TotalPayload payload{};
    Secret secret{};
    sockaddr_in peer{};
    Clock::time_point deadline{};

    ~Session() {
        secure_zero(&payload, sizeof(payload));
        secure_zero(secret.data(), secret.size());
    }
};

bool same_peer(const sockaddr_in& a, const sockaddr_in& b) {
    return a.sin_family == b.sin_family &&
           a.sin_addr.s_addr == b.sin_addr.s_addr &&
           a.sin_port == b.sin_port;
}

template<std::size_t N>
void fill_random(std::array<std::uint8_t, N>& bytes, std::random_device& rng) {
    for (auto& byte : bytes) {
        byte = static_cast<std::uint8_t>(rng());
    }
}

std::uint16_t parse_port(const char* value) {
    std::size_t length = 0;
    const unsigned long port = std::stoul(value, &length);
    if (value[length] != '\0' || port > 65535) {
        throw std::invalid_argument("Invalid port");
    }
    return static_cast<std::uint16_t>(port);
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: server <bind-ipv4> <port> (0 = free port)\n";
        return 1;
    }

    try {
        sockaddr_in address{};
        address.sin_family = AF_INET;
        if (::inet_pton(AF_INET, argv[1], &address.sin_addr) != 1) {
            throw std::invalid_argument("Invalid IPv4 address");
        }
        address.sin_port = htons(parse_port(argv[2]));

        UdpMessageChannel channel;
        const auto port = channel.bind(address);
        channel.set_receive_timeout(std::chrono::milliseconds(200));
        std::cout << "listening " << argv[1] << ':' << port << std::endl;

        std::random_device rng;
        std::unordered_set<std::uint32_t> used_ids;
        std::optional<Session> session;

        for (;;) {
            if (session && Clock::now() >= session->deadline) {
                session.reset();
            }

            sockaddr_in sender{};
            if (!session) {
                std::optional<std::uint32_t> exchange_id;
                auto init = channel.receive<ClientRandom>(MessageType::INIT,
                                                          exchange_id, sender, std::cerr);
                if (!init) {
                    continue;
                }

                const std::uint32_t id = *exchange_id;
                if (!used_ids.insert(id).second) {
                    std::cerr << "Repeated exchange_id: " << id << '\n';
                    secure_zero(init->client_random.data(), init->client_random.size());
                    continue;
                }

                session.emplace();
                session->payload.exchange_id = id;
                session->payload.client_random = init->client_random;
                session->peer = sender;
                session->deadline = Clock::now() + std::chrono::seconds(5);
                fill_random(session->payload.server_random, rng);
                fill_random(session->payload.nonce, rng);
                session->secret = Calculate_secret(session->payload);

                InitAckPayload reply{};
                reply.server_random = session->payload.server_random;
                reply.nonce = session->payload.nonce;
                if (!channel.send(MessageType::INIT_ACK, id, reply, sender, std::cerr)) {
                    secure_zero(&reply, sizeof(reply));
                    secure_zero(init->client_random.data(), init->client_random.size());
                    session.reset();
                    continue;
                }
                secure_zero(&reply, sizeof(reply));
                secure_zero(init->client_random.data(), init->client_random.size());
                continue;
            }

            std::optional<std::uint32_t> exchange_id = session->payload.exchange_id;
            auto confirm = channel.receive<HMAC>(MessageType::CONFIRM,
                                                 exchange_id, sender, std::cerr);
            if (!confirm) {
                continue;
            }
            if (Clock::now() >= session->deadline) {
                session.reset();
                continue;
            }
            if (!same_peer(sender, session->peer)) {
                std::cerr << "Unexpected sender\n";
                continue;
            }

            HMAC expected = Calculate_hmac(session->secret, MessageType::CONFIRM,
                                           session->payload);
            const bool valid = *confirm == expected;
            secure_zero(expected.hmac.data(), expected.hmac.size());
            if (!valid) {
                std::cerr << "Invalid HMAC\n";
                session.reset();
                continue;
            }

            HMAC ack = Calculate_hmac(session->secret, MessageType::CONFIRM_ACK,
                                      session->payload);
            const bool sent = channel.send(MessageType::CONFIRM_ACK,
                                           session->payload.exchange_id,
                                           ack, sender, std::cerr);
            secure_zero(ack.hmac.data(), ack.hmac.size());
            if (sent) {
                std::cout << "ok exchange=" << session->payload.exchange_id << std::endl;
            }
            session.reset();
        }
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
