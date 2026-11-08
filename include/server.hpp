#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <unordered_set>

#include "cryptography.hpp"
#include "udp_channel.hpp"

class ConfirmReceiveState {
public:
    ConfirmReceiveState(UdpChannel& channel, std::unique_ptr<CryptoContext> crypto,
                        std::uint32_t exchange_id, UdpAddress peer,
                        std::chrono::steady_clock::time_point deadline)
        : channel_(channel), crypto_(std::move(crypto)), exchange_id_(exchange_id),
          peer_(std::move(peer)), deadline_(deadline) {}

    std::optional<std::uint32_t> run() {
        using namespace std::chrono;
        while (steady_clock::now() < deadline_) {
            const auto remaining = ceil<milliseconds>(deadline_ - steady_clock::now());
            std::optional<std::uint32_t> id = exchange_id_;
            std::optional<UdpAddress> sender = peer_;
            auto confirm = channel_.receive<32>(MessageType::CONFIRM, id, sender, remaining);
            if (!confirm) {
                continue;
            }
            if (steady_clock::now() >= deadline_) {
                break;
            }

            const auto expected = crypto_->calculate_hmac(MessageType::CONFIRM, exchange_id_);
            std::uint8_t difference = 0;
            for (std::size_t i = 0; i < confirm->size(); ++i) {
                difference |= (*confirm)[i] ^ expected[i];
            }
            if (difference != 0) {
                std::cerr << "Invalid HMAC\n";
                continue;
            }
            if (steady_clock::now() >= deadline_) {
                continue;
            }

            const auto ack = crypto_->calculate_hmac(MessageType::CONFIRM_ACK, exchange_id_);
            if (steady_clock::now() >= deadline_) {
                break;
            }
            if (!channel_.send(MessageType::CONFIRM_ACK, exchange_id_, ack, peer_)) {
                std::cerr << "sendto CONFIRM_ACK failed\n";
                return std::nullopt;
            }
            return exchange_id_;
        }
        return std::nullopt;
    }

private:
    UdpChannel& channel_;
    std::unique_ptr<CryptoContext> crypto_;
    std::uint32_t exchange_id_;
    UdpAddress peer_;
    std::chrono::steady_clock::time_point deadline_;
};

class InitReceiveState {
public:
    InitReceiveState(UdpChannel& channel, std::unordered_set<std::uint32_t>& used_ids)
        : channel_(channel), used_ids_(used_ids) {}

    std::optional<ConfirmReceiveState> run() {
        using Clock = std::chrono::steady_clock;
        for (;;) {
            std::optional<std::uint32_t> id;
            std::optional<UdpAddress> sender;
            auto init = channel_.receive<32>(MessageType::INIT, id, sender);
            if (!init) {
                continue;
            }
            if (!used_ids_.insert(*id).second) {
                std::cerr << "Repeated exchange_id: " << *id << '\n';
                secure_zero(init->data(), init->size());
                continue;
            }

            const auto deadline = Clock::now() + std::chrono::seconds(5);
            auto crypto = std::make_unique<CryptoContext>();
            crypto->client_random = *init;
            secure_zero(init->data(), init->size());
            for (auto& byte : crypto->server_random) {
                byte = static_cast<std::uint8_t>(random_());
            }
            for (auto& byte : crypto->nonce) {
                byte = static_cast<std::uint8_t>(random_());
            }
            crypto->calculate_secret(*id);

            std::array<std::uint8_t, 64> reply{};
            std::copy(crypto->server_random.begin(), crypto->server_random.end(), reply.begin());
            std::copy(crypto->nonce.begin(), crypto->nonce.end(), reply.begin() + 32);
            const bool sent = channel_.send(MessageType::INIT_ACK, *id, reply, *sender);
            secure_zero(reply.data(), reply.size());
            if (!sent) {
                std::cerr << "sendto INIT_ACK failed\n";
                return std::nullopt;
            }
            return std::optional<ConfirmReceiveState>{
                std::in_place, channel_, std::move(crypto), *id, std::move(*sender), deadline
            };
        }
    }

private:
    UdpChannel& channel_;
    std::unordered_set<std::uint32_t>& used_ids_;
    std::random_device random_;
};

class Server {
public:
    std::optional<UdpAddress> bind(const UdpAddress& address) {
        return channel_.bind(address);
    }

    void run() {
        InitReceiveState init{channel_, used_ids_};
        for (;;) {
            auto confirm = init.run();
            if (confirm) {
                const auto success = confirm->run();
                if (success) {
                    std::cout << "ok exchange=" << *success << std::endl;
                }
            }
        }
    }

private:
    UdpChannel channel_;
    std::unordered_set<std::uint32_t> used_ids_;
};
