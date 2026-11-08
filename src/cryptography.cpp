#include "cryptography.hpp"
#include "secure_zero.h"

extern "C" {
#include "sha256.h"
}

namespace {

void update_exchange_id(SHA256_CTX& ctx, std::uint32_t exchange_id) {
    // Network order, независимо от порядка байтов процессора.
    const std::uint8_t bytes[] = {
        static_cast<std::uint8_t>(exchange_id >> 24),
        static_cast<std::uint8_t>(exchange_id >> 16),
        static_cast<std::uint8_t>(exchange_id >> 8),
        static_cast<std::uint8_t>(exchange_id)
    };
    sha256_update(&ctx, bytes, sizeof(bytes));
}

} // namespace

Secret Calculate_secret(const TotalPayload& payload) {
    SHA256_CTX ctx{};
    Secret secret{};
    sha256_init(&ctx);
    sha256_update(&ctx, payload.client_random.data(), payload.client_random.size());
    sha256_update(&ctx, payload.server_random.data(), payload.server_random.size());
    sha256_update(&ctx, payload.nonce.data(), payload.nonce.size());
    update_exchange_id(ctx, payload.exchange_id);
    sha256_final(&ctx, secret.data());
    secure_zero(&ctx, sizeof(ctx));
    return secret;
}

HMAC Calculate_hmac(const Secret& secret, MessageType type,
                    const TotalPayload& payload) {
    constexpr std::size_t block_size = 64;
    std::array<std::uint8_t, block_size> inner_pad{};
    std::array<std::uint8_t, block_size> outer_pad{};
    for (std::size_t i = 0; i < block_size; ++i) {
        const std::uint8_t key_byte = i < secret.size() ? secret[i] : 0;
        inner_pad[i] = key_byte ^ 0x36;
        outer_pad[i] = key_byte ^ 0x5c;
    }

    SHA256_CTX ctx{};
    Secret inner_hash{};
    sha256_init(&ctx);
    sha256_update(&ctx, inner_pad.data(), inner_pad.size());
    const auto type_byte = static_cast<std::uint8_t>(type);
    sha256_update(&ctx, &type_byte, sizeof(type_byte));
    update_exchange_id(ctx, payload.exchange_id);
    sha256_update(&ctx, payload.client_random.data(), payload.client_random.size());
    sha256_update(&ctx, payload.server_random.data(), payload.server_random.size());
    sha256_update(&ctx, payload.nonce.data(), payload.nonce.size());
    sha256_final(&ctx, inner_hash.data());

    HMAC result{};
    sha256_init(&ctx);
    sha256_update(&ctx, outer_pad.data(), outer_pad.size());
    sha256_update(&ctx, inner_hash.data(), inner_hash.size());
    sha256_final(&ctx, result.hmac.data());
    secure_zero(&ctx, sizeof(ctx));
    secure_zero(inner_hash.data(), inner_hash.size());
    secure_zero(inner_pad.data(), inner_pad.size());
    secure_zero(outer_pad.data(), outer_pad.size());
    return result;
}
