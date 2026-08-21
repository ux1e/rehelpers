// pattern_scanner.hpp
//
// Сигнатурный поиск байтовых паттернов с wildcard-байтами (в стиле IDA:
// "48 8B 05 ?? ?? ?? ?? 48 85 C0"). Используется, чтобы находить адреса
// функций/структур в бинарнике по устойчивой последовательности байт,
// когда явных символов/экспортов нет (либо они после обновления сместились).
//
// Header-only, без внешних зависимостей.

#pragma once

#include <cstdint>
#include <cstddef>
#include <string_view>
#include <vector>
#include <optional>
#include <stdexcept>

namespace rehelpers {

struct PatternByte {
    std::uint8_t value = 0;
    bool wildcard = false;
};

// Разбирает строку паттерна вида "48 8B ?? 05" в список байт/wildcard.
// "?" и "??" оба трактуются как wildcard-байт.
inline std::vector<PatternByte> parse_pattern(std::string_view pattern) {
    std::vector<PatternByte> result;
    size_t i = 0;
    while (i < pattern.size()) {
        while (i < pattern.size() && pattern[i] == ' ') ++i;
        if (i >= pattern.size()) break;

        size_t start = i;
        while (i < pattern.size() && pattern[i] != ' ') ++i;
        std::string_view token = pattern.substr(start, i - start);

        if (token == "?" || token == "??") {
            result.push_back(PatternByte{0, true});
            continue;
        }
        if (token.size() != 2) {
            throw std::invalid_argument("rehelpers::parse_pattern: bad token '" +
                                         std::string(token) + "'");
        }
        auto hex_val = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            throw std::invalid_argument("rehelpers::parse_pattern: bad hex digit");
        };
        std::uint8_t byte = static_cast<std::uint8_t>((hex_val(token[0]) << 4) | hex_val(token[1]));
        result.push_back(PatternByte{byte, false});
    }
    return result;
}

// Ищет первое вхождение паттерна в [begin, begin + size).
// Возвращает указатель на начало совпадения либо nullptr.
inline void* find_pattern(const std::uint8_t* begin, std::size_t size, std::string_view pattern) {
    const auto needle = parse_pattern(pattern);
    if (needle.empty() || needle.size() > size) return nullptr;

    const std::size_t last = size - needle.size();
    for (std::size_t offset = 0; offset <= last; ++offset) {
        bool match = true;
        for (std::size_t j = 0; j < needle.size(); ++j) {
            if (!needle[j].wildcard && begin[offset + j] != needle[j].value) {
                match = false;
                break;
            }
        }
        if (match) {
            return const_cast<std::uint8_t*>(begin + offset);
        }
    }
    return nullptr;
}

// Находит все вхождения паттерна (полезно, когда сигнатура неуникальна
// и нужно вручную выбрать нужный результат).
inline std::vector<void*> find_pattern_all(const std::uint8_t* begin, std::size_t size,
                                            std::string_view pattern) {
    const auto needle = parse_pattern(pattern);
    std::vector<void*> results;
    if (needle.empty() || needle.size() > size) return results;

    const std::size_t last = size - needle.size();
    for (std::size_t offset = 0; offset <= last; ++offset) {
        bool match = true;
        for (std::size_t j = 0; j < needle.size(); ++j) {
            if (!needle[j].wildcard && begin[offset + j] != needle[j].value) {
                match = false;
                break;
            }
        }
        if (match) {
            results.push_back(const_cast<std::uint8_t*>(begin + offset));
        }
    }
    return results;
}

} // namespace rehelpers
