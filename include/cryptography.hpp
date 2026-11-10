#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>

#include "secure_zero.h"
#include "udp_channel.hpp"
#include "secure_bytes.hpp"

extern "C" {
#include "../third_party/sha-256.h"
}

class CryptoContext {
public:
    SecureBytes<32> client_random{};
    SecureBytes<32> server_random{};
    SecureBytes<32> nonce{};

    CryptoContext() = default;
    CryptoContext(const CryptoContext&) = delete;
    CryptoContext& operator=(const CryptoContext&) = delete;
    CryptoContext(CryptoContext&&) = delete;
    CryptoContext& operator=(CryptoContext&&) = delete;

    ~CryptoContext() {
        secure_zero(client_random.data(), client_random.size());
        secure_zero(server_random.data(), server_random.size());
        secure_zero(nonce.data(), nonce.size());
        secure_zero(secret_.data(), secret_.size());
    }

    void calculate_secret(std::uint32_t exchange_id) {
        secret_ready_ = false;
        secure_zero(secret_.data(), secret_.size());
        const auto id = id_bytes(exchange_id);
        Sha_256 ctx{};
        sha_256_init(&ctx, secret_.data());
        sha_256_write(&ctx, client_random.data(), client_random.size());
        sha_256_write(&ctx, server_random.data(), server_random.size());
        sha_256_write(&ctx, nonce.data(), nonce.size());
        sha_256_write(&ctx, id.data(), id.size());
        sha_256_close(&ctx);
        secure_zero(&ctx, sizeof(ctx));
        secret_ready_ = true;
    }

    SecureBytes<32> calculate_hmac(
        MessageType type, std::uint32_t exchange_id
    ) const {
        if (!secret_ready_) {
            throw std::logic_error("secret has not been calculated");
        }

        SecureBytes<64> inner_pad{};
        SecureBytes<64> outer_pad{};
        for (std::size_t i = 0; i < inner_pad.size(); ++i) {
            const std::uint8_t key_byte = i < secret_.size() ? secret_[i] : 0;
            inner_pad[i] = key_byte ^ 0x36;
            outer_pad[i] = key_byte ^ 0x5c;
        }

        const std::uint8_t type_byte = static_cast<std::uint8_t>(type);
        const auto id = id_bytes(exchange_id);
        Sha_256 inner_ctx{};
        SecureBytes<32> inner_digest{};
        sha_256_init(&inner_ctx, inner_digest.data());
        sha_256_write(&inner_ctx, inner_pad.data(), inner_pad.size());
        sha_256_write(&inner_ctx, &type_byte, sizeof(type_byte));
        sha_256_write(&inner_ctx, id.data(), id.size());
        sha_256_write(&inner_ctx, client_random.data(), client_random.size());
        sha_256_write(&inner_ctx, server_random.data(), server_random.size());
        sha_256_write(&inner_ctx, nonce.data(), nonce.size());
        sha_256_close(&inner_ctx);
        secure_zero(&inner_ctx, sizeof(inner_ctx));

        Sha_256 outer_ctx{};
        SecureBytes<32> tag{};
        sha_256_init(&outer_ctx, tag.data());
        sha_256_write(&outer_ctx, outer_pad.data(), outer_pad.size());
        sha_256_write(&outer_ctx, inner_digest.data(), inner_digest.size());
        sha_256_close(&outer_ctx);

        secure_zero(&outer_ctx, sizeof(outer_ctx));
        return tag;
    }

private:
    static std::array<std::uint8_t, 4> id_bytes(std::uint32_t exchange_id) {
        return {{static_cast<std::uint8_t>(exchange_id >> 24),
                 static_cast<std::uint8_t>(exchange_id >> 16),
                 static_cast<std::uint8_t>(exchange_id >> 8),
                 static_cast<std::uint8_t>(exchange_id)}};
    }

    SecureBytes<32> secret_{};
    bool secret_ready_ = false;
};
