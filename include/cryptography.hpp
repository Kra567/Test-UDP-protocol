#pragma once

#include <array>
#include <cstdint>

#include "messages.hpp"

using Secret = std::array<std::uint8_t, 32>;

Secret Calculate_secret(const TotalPayload& payload);
HMAC Calculate_hmac(const Secret& secret, MessageType type,
                    const TotalPayload& payload);
