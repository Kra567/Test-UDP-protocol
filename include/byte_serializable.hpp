#pragma once

#include <cstdint>
#include <type_traits>
#include <array>
#include <cstddef>

// Сериализация в байты (сразу интерфейс и объявление абстрактное для типов с одним полем)
// 1. десереализация
// 2. сереализация
// 3. размер в байтах

template<typename T, typename Enable = void>
class ByteSerializable {
public:
    static T deserialize(uint8_t*& ptr) {
        T result{};

        auto& [field] = result;
        using Field = std::decay_t<decltype(field)>;

        field = ByteSerializable<Field>::deserialize(ptr);
        return result;
    }

    static void serialize(const T& val, uint8_t*& ptr) {
        const auto& [field] = val;
        using Field = std::decay_t<decltype(field)>;

        ByteSerializable<Field>::serialize(field, ptr);
    }

    static constexpr std::size_t byte_size() {
        T val{};
        const auto& [field] = val;
        using Field = std::decay_t<decltype(field)>;

        return ByteSerializable<Field>::byte_size();
    }
};

// Все беззнаковые целочисленные типы
template<typename T>
class ByteSerializable<
    T,
    std::enable_if_t<
        std::is_integral_v<T> && std::is_unsigned_v<T>
    >
> {
public:
    static T deserialize(uint8_t*& ptr);
    static void serialize(const T& val, uint8_t*& ptr);
    static constexpr std::size_t byte_size();
};

template<typename... Ts>
struct Combined : Ts... {};

template<typename... Ts>
class ByteSerializable<Combined<Ts...>> {
public:
    static Combined<Ts...> deserialize(std::uint8_t*& ptr) {
        return Combined<Ts...>{
            ByteSerializable<Ts>::deserialize(ptr)...
        };
    }

    static void serialize(
        const Combined<Ts...>& val,
        std::uint8_t*& ptr
    ) {
        (
            ByteSerializable<Ts>::serialize(
                static_cast<const Ts&>(val),
                ptr
            ),
            ...
        );
    }

    static constexpr std::size_t byte_size() {
        return (
            std::size_t{0} + ... +
            ByteSerializable<Ts>::byte_size()
        );
    }
};

template<std::size_t N>
class ByteSerializable<std::array<uint8_t, N>> {
public:
    static std::array<uint8_t, N> deserialize(uint8_t*& ptr);

    static void serialize(
        const std::array<uint8_t, N>& val,
        uint8_t*& ptr
    );

    static constexpr std::size_t byte_size();
};

template<typename T>
T ByteSerializable<
    T,
    std::enable_if_t<
        std::is_integral_v<T> && std::is_unsigned_v<T>
    >
>::deserialize(uint8_t*& ptr) {
    T result = 0;

    for (std::size_t i = 0; i < sizeof(T); ++i) {
        result = static_cast<T>((result << 8) | *ptr++);
    }

    return result;
}

template<typename T>
void ByteSerializable<
    T,
    std::enable_if_t<
        std::is_integral_v<T> && std::is_unsigned_v<T>
    >
>::serialize(const T& val, uint8_t*& ptr) {
    for (std::size_t i = sizeof(T); i > 0; --i) {
        *ptr++ = static_cast<uint8_t>(
            val >> ((i - 1) * 8)
        );
    }
}

template<typename T>
constexpr std::size_t ByteSerializable<
    T,
    std::enable_if_t<
        std::is_integral_v<T> && std::is_unsigned_v<T>
    >
>::byte_size() {
    return sizeof(T);
}


template<std::size_t N>
std::array<uint8_t, N>
ByteSerializable<std::array<uint8_t, N>>::deserialize(
    uint8_t*& ptr
) {
    std::array<uint8_t, N> result{};

    for (std::size_t i = 0; i < N; ++i) {
        result[i] = *ptr++;
    }

    return result;
}

template<std::size_t N>
void ByteSerializable<std::array<uint8_t, N>>::serialize(
    const std::array<uint8_t, N>& val,
    uint8_t*& ptr
) {
    for (uint8_t byte : val) {
        *ptr++ = byte;
    }
}

template<std::size_t N>
constexpr std::size_t ByteSerializable<std::array<uint8_t, N>>::byte_size() {
    return N;
}
