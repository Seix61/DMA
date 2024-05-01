
#include <util/codec/url.h>

namespace Codec {
    std::string Url::encode(const std::string &input) {
        std::string encoded;
        encoded.reserve(input.size() * 3);

        for (char c: input) {
            if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                encoded += c;
            } else if (c == ' ') {
                encoded += '+';
            } else {
                encoded += '%';
                encoded += (c / 16 < 10) ? '0' + (c / 16) : 'A' + (c / 16 - 10);
                encoded += (c % 16 < 10) ? '0' + (c % 16) : 'A' + (c % 16 - 10);
            }
        }

        return encoded;
    }

    std::string Url::decode(const std::string &input) {
        std::string decoded;
        decoded.reserve(input.size());

        for (size_t i = 0; i < input.size(); ++i) {
            if (input[i] == '%') {
                if (i + 2 < input.size()) {
                    int hex_value = 0;
                    for (int j = 0; j < 2; ++j) {
                        char c = input[i + 1 + j];
                        hex_value *= 16;
                        hex_value += (c >= '0' && c <= '9') ? (c - '0') :
                                     (c >= 'A' && c <= 'F') ? (c - 'A' + 10) :
                                     (c >= 'a' && c <= 'f') ? (c - 'a' + 10) : 0;
                    }
                    decoded += static_cast<char>(hex_value);
                    i += 2;
                } else {
                    // Incomplete percent encoding, treat as a literal character
                    decoded += input[i];
                }
            } else if (input[i] == '+') {
                decoded += ' ';
            } else {
                decoded += input[i];
            }
        }

        return decoded;
    }

    std::string Url::encode(const char *input, int length) {
        return encode(std::string(input, length));
    }

    std::string Url::decode(const char *input, int length) {
        return decode(std::string(input, length));
    }
}