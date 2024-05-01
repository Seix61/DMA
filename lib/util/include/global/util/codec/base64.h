
#ifndef LIB_UTIL_CODEC_BASE64_H
#define LIB_UTIL_CODEC_BASE64_H

#include <string>

namespace Codec {
    class Base64 {
    private:
        static std::string chars;

        static inline bool isBase64(unsigned char c);

    public:
        static std::string encode(const std::string &input);

        static std::string encode(const char *input, int length);

        static std::string encode(const unsigned char *input, int length);

        static std::string decode(const std::string &input);

        static std::string decode(const char *input, int length);
    };
}

#endif //LIB_UTIL_CODEC_BASE64_H
