#pragma once

#include "byte_serializable.hpp"
#include <cstdint>


struct Magic  {uint32_t magic = 0x4B455931;};
struct Version {uint8_t version = 1;};
struct Flags {uint8_t flags = 0;};
struct Reserved {uint8_t reserved = 0;};

enum class MessageType : std::uint8_t {
    INIT = 1,
    INIT_ACK = 2,
    CONFIRM = 3,
    CONFIRM_ACK = 4
};

struct Type {
    std::uint8_t type;
};

struct ExchangeId { std::uint32_t exchange_id; };


struct Nonce { std::array<uint8_t, 32> nonce; };

struct ClientRandom { std::array<uint8_t, 32> client_random; };
struct ServerRandom { std::array<uint8_t, 32> server_random; };

using TotalPayload = Combined<ExchangeId, ClientRandom, ServerRandom, Nonce>;

struct HMAC {
    std::array<std::uint8_t, 32> hmac;

    bool operator==(const HMAC& other) const {
        std::uint8_t diff = 0;

        for (std::size_t i = 0; i < hmac.size(); ++i) {
            diff |= hmac[i] ^ other.hmac[i];
        }

        return diff == 0;
    }
};

// header
using Header =
    Combined<
        Magic,
        Version,
        Type,
        Flags,
        Reserved,
        ExchangeId
    >;
