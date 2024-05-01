
#include <util/codec/hex.h>
#include <iomanip>

namespace Codec {
    std::string Hex::encode(const std::string &input) {
        std::ostringstream encoded;
        encoded << std::hex << std::setfill('0');

        for (unsigned char c: input) {
            encoded << std::setw(2) << static_cast<int>(c);
        }

        return encoded.str();
    }

    std::string Hex::decode(const std::string &input) {
        std::string decoded;

        for (size_t i = 0; i < input.length(); i += 2) {
            std::string hex_byte = input.substr(i, 2);
            char c = static_cast<char>(std::stoi(hex_byte, nullptr, 16));
            decoded.push_back(c);
        }

        return decoded;
    }

    std::string Hex::encode(const char *input, int length) {
        return encode(std::string(input, length));
    }

    std::string Hex::decode(const char *input, int length) {
        return decode(std::string(input, length));
    }
}