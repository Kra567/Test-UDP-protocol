#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "secure_zero.h"

extern "C" {
#include "../third_party/sha256.h"
}

template<std::size_t N>
std::array<std::uint8_t, 32> sha256(const std::array<std::uint8_t, N>& data) {
    SHA256_CTX ctx{};
    std::array<std::uint8_t, 32> digest{};

    sha256_init(&ctx);
    sha256_update(&ctx, data.data(), data.size());
    sha256_final(&ctx, digest.data());
    secure_zero(&ctx, sizeof(ctx));

    return digest;
}

template<std::size_t N>
std::array<std::uint8_t, 32> hmac_sha256(
    const std::array<std::uint8_t, 32>& secret,
    const std::array<std::uint8_t, N>& data
) {
    std::array<std::uint8_t, 64> inner_pad{};
    std::array<std::uint8_t, 64> outer_pad{};
    for (std::size_t i = 0; i < inner_pad.size(); ++i) {
        const std::uint8_t key_byte = i < secret.size() ? secret[i] : 0;
        inner_pad[i] = key_byte ^ 0x36;
        outer_pad[i] = key_byte ^ 0x5c;
    }

    SHA256_CTX inner_ctx{};
    std::array<std::uint8_t, 32> inner_digest{};
    sha256_init(&inner_ctx);
    sha256_update(&inner_ctx, inner_pad.data(), inner_pad.size());
    sha256_update(&inner_ctx, data.data(), data.size());
    sha256_final(&inner_ctx, inner_digest.data());
    secure_zero(&inner_ctx, sizeof(inner_ctx));

    SHA256_CTX outer_ctx{};
    std::array<std::uint8_t, 32> digest{};
    sha256_init(&outer_ctx);
    sha256_update(&outer_ctx, outer_pad.data(), outer_pad.size());
    sha256_update(&outer_ctx, inner_digest.data(), inner_digest.size());
    sha256_final(&outer_ctx, digest.data());

    secure_zero(&outer_ctx, sizeof(outer_ctx));
    secure_zero(inner_pad.data(), inner_pad.size());
    secure_zero(outer_pad.data(), outer_pad.size());
    secure_zero(inner_digest.data(), inner_digest.size());
    return digest;
}
