
#include <util/codec/base64.h>

namespace Codec {
    std::string Base64::chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    bool Base64::isBase64(unsigned char c) {
        return (isalnum(c) || (c == '+') || (c == '/'));
    }

    std::string Base64::encode(const std::string &input) {
        std::string ret;
        size_t in_len = input.size();
        int i = 0;
        int j = 0;
        unsigned char char_array_3[3];
        unsigned char char_array_4[4];

        for (size_t in_ = 0; in_ < in_len; ++in_) {
            char_array_3[i++] = input[in_];
            if (i == 3) {
                char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
                char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
                char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
                char_array_4[3] = char_array_3[2] & 0x3f;

                for (i = 0; i < 4; ++i)
                    ret += chars[char_array_4[i]];
                i = 0;
            }
        }

        if (i) {
            for (j = i; j < 3; ++j)
                char_array_3[j] = '\0';

            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (j = 0; j < i + 1; ++j)
                ret += chars[char_array_4[j]];

            while (i++ < 3)
                ret += '=';
        }

        return ret;
    }

    std::string Base64::decode(const std::string &input) {
        int in_len = input.size();
        int i = 0;
        int j = 0;
        int in_ = 0;
        unsigned char char_array_4[4], char_array_3[3];
        std::string ret;

        while (in_len-- && (input[in_] != '=') && isBase64(input[in_])) {
            char_array_4[i++] = input[in_];
            in_++;
            if (i == 4) {
                for (i = 0; i < 4; i++)
                    char_array_4[i] = chars.find(char_array_4[i]);

                char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                for (i = 0; i < 3; i++)
                    ret += char_array_3[i];
                i = 0;
            }
        }

        if (i) {
            for (j = i; j < 4; j++)
                char_array_4[j] = 0;

            for (j = 0; j < 4; j++)
                char_array_4[j] = chars.find(char_array_4[j]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (j = 0; j < i - 1; j++)
                ret += char_array_3[j];
        }

        return ret;
    }

    std::string Base64::encode(const char *input, int length) {
        return encode(std::string(input, length));
    }

    std::string Base64::encode(const unsigned char *input, int length) {
        return encode((const char *) input, length);
    }

    std::string Base64::decode(const char *input, int length) {
        return decode(std::string(input, length));
    }
}
