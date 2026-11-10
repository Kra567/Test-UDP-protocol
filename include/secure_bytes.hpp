#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "secure_zero.h"

template <std::size_t N>
struct SecureBytes : std::array<std::uint8_t, N> {
    SecureBytes() {
        this->fill(0);
    }

    ~SecureBytes() {
        secure_zero(this->data(), this->size());
    }
};
