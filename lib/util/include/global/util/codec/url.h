
#ifndef LIB_UTIL_CODEC_URL_H
#define LIB_UTIL_CODEC_URL_H

#include <string>

namespace Codec {
    class Url {
    public:
        static std::string encode(const std::string &input);

        static std::string encode(const char *input, int length);

        static std::string decode(const std::string &input);

        static std::string decode(const char *input, int length);
    };
}

#endif //LIB_UTIL_CODEC_URL_H
