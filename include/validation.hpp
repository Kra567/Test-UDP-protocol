
#pragma once

#include <ostream>
#include <type_traits>
#include <typeinfo>
#include <utility>

#include "byte_serializable.hpp"


template<typename T, typename = void>
struct HasEqual : std::false_type {};

template<typename T>
struct HasEqual<
    T,
    std::void_t<decltype(
        std::declval<const T&>() == std::declval<const T&>()
    )>
> : std::true_type {};


// Используем operator==, если он есть.
// Иначе сравниваем единственное поле структуры.
template<typename T>
bool equal(const T& a, const T& b) {
    if constexpr (HasEqual<T>::value) {
        return a == b;
    } else {
        const auto& [x] = a;
        const auto& [y] = b;
        return x == y;
    }
}


// Предварительные объявления для рекурсии.
template<typename T, typename ENV>
bool compare(const T& value, const ENV& expected, std::ostream& log);

template<typename... Ts, typename ENV>
bool compare(
    const Combined<Ts...>& value,
    const ENV& expected,
    std::ostream& log
);


// Сравнение отдельного поля.
template<typename T, typename ENV>
bool compare(
    const T& value,
    const ENV& expected,
    std::ostream& log
) {
    if constexpr (std::is_base_of_v<T, ENV>) {
        if (!equal(value, static_cast<const T&>(expected))) {
            log << "Invalid field: " << typeid(T).name() << '\n';
            return false;
        }
    }

    return true;
}


// Рекурсивное сравнение Combined.
template<typename... Ts, typename ENV>
bool compare(
    const Combined<Ts...>& value,
    const ENV& expected,
    std::ostream& log
) {
    bool valid = true;

    ((valid = compare(
        static_cast<const Ts&>(value),
        expected,
        log
    ) & valid), ...);

    return valid;
}
