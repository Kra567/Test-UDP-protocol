#pragma once

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <utility>

#include "cryptography.hpp"
#include "udp_channel.hpp"
#include "secure_bytes.hpp"

class ConfirmAckReceiveState {
public:
    ConfirmAckReceiveState(UdpChannel& channel, std::unique_ptr<CryptoContext> crypto,
                           std::uint32_t exchange_id, UdpAddress server,
                           std::chrono::steady_clock::time_point deadline)
        : channel_(channel), crypto_(std::move(crypto)), exchange_id_(exchange_id),
          server_(std::move(server)), deadline_(deadline) {}

    std::optional<std::uint32_t> run() {
        using namespace std::chrono;
        if (steady_clock::now() >= deadline_) {
            std::cerr << "CONFIRM_ACK timeout\n";
            return std::nullopt;
        }

        const auto confirm = crypto_->calculate_hmac(MessageType::CONFIRM, exchange_id_);
        if (steady_clock::now() >= deadline_) {
            std::cerr << "CONFIRM_ACK timeout\n";
            return std::nullopt;
        }
        if (!channel_.send(MessageType::CONFIRM, exchange_id_, confirm, server_)) {
            std::cerr << "sendto CONFIRM failed\n";
            return std::nullopt;
        }

        while (steady_clock::now() < deadline_) {
            const auto remaining = ceil<milliseconds>(deadline_ - steady_clock::now());
            std::optional<std::uint32_t> id = exchange_id_;
            std::optional<UdpAddress> sender = server_;
            auto ack = channel_.receive<32>(MessageType::CONFIRM_ACK, id, sender, remaining);
            if (!ack) {
                continue;
            }
            if (steady_clock::now() >= deadline_) {
                break;
            }

            const auto expected = crypto_->calculate_hmac(MessageType::CONFIRM_ACK, exchange_id_);
            std::uint8_t difference = 0;
            for (std::size_t i = 0; i < ack->size(); ++i) {
                difference |= (*ack)[i] ^ expected[i];
            }
            if (difference == 0 && steady_clock::now() < deadline_) {
                return exchange_id_;
            }
            if (difference != 0) {
                std::cerr << "Invalid CONFIRM_ACK HMAC\n";
            }
        }
        std::cerr << "CONFIRM_ACK timeout\n";
        return std::nullopt;
    }

private:
    UdpChannel& channel_;
    std::unique_ptr<CryptoContext> crypto_;
    std::uint32_t exchange_id_;
    UdpAddress server_;
    std::chrono::steady_clock::time_point deadline_;
};

class InitAckReceiveState {
public:
    InitAckReceiveState(UdpChannel& channel, UdpAddress server)
        : channel_(channel), server_(std::move(server)) {}

    std::optional<ConfirmAckReceiveState> run() {
        using namespace std::chrono;
        auto crypto = std::make_unique<CryptoContext>();
        const auto exchange_id = static_cast<std::uint32_t>(random_());
        for (auto& byte : crypto->client_random) {
            byte = static_cast<std::uint8_t>(random_());
        }

        const auto deadline = steady_clock::now() + seconds(5);
        if (!channel_.send(MessageType::INIT, exchange_id,
                           crypto->client_random, server_)) {
            std::cerr << "sendto INIT failed\n";
            return std::nullopt;
        }

        while (steady_clock::now() < deadline) {
            const auto remaining = ceil<milliseconds>(deadline - steady_clock::now());
            std::optional<std::uint32_t> id = exchange_id;
            std::optional<UdpAddress> sender = server_;
            auto ack = channel_.receive<64>(MessageType::INIT_ACK, id, sender, remaining);
            if (!ack) {
                continue;
            }
            if (steady_clock::now() >= deadline) {
                break;
            }

            std::copy_n(ack->begin(), 32, crypto->server_random.begin());
            std::copy_n(ack->begin() + 32, 32, crypto->nonce.begin());
            crypto->calculate_secret(exchange_id);
            return std::optional<ConfirmAckReceiveState>{
                std::in_place, channel_, std::move(crypto), exchange_id, server_, deadline
            };
        }
        std::cerr << "INIT_ACK timeout\n";
        return std::nullopt;
    }

private:
    UdpChannel& channel_;
    UdpAddress server_;
    std::random_device random_;
};

class Client {
public:
    explicit Client(UdpAddress server) : server_(std::move(server)) {}

    bool run() {
        InitAckReceiveState init{channel_, server_};
        auto confirm = init.run();
        if (!confirm) {
            return false;
        }
        const auto success = confirm->run();
        if (!success) {
            return false;
        }
        std::cout << "ok exchange=" << *success << std::endl;
        return true;
    }

private:
    UdpChannel channel_;
    UdpAddress server_;
};
