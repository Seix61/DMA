
#include <util/ip.h>
#include <cstdlib>
#include <cstring>
#include <cstdio>

unsigned long IPUtil::ipAddr2ULong(const char *str) {
    unsigned long lHost = 0;
    char *pLong = (char *) &lHost;
    char *p = (char *) str;
    while (p) {
        *pLong++ = atoi(p);
        p = strchr(p, '.');
        if (p) {
            ++p;
        }
    }
    return lHost;
}

char *IPUtil::uLong2IpAddr(unsigned long lHost) {
    char *str = (char *) malloc(16);
    if (str == nullptr) {
        return nullptr;
    }

    char *pLong = (char *) &lHost;
    int written = snprintf(str, 16, "%u.%u.%u.%u", (unsigned char) pLong[0], (unsigned char) pLong[1],
                           (unsigned char) pLong[2], (unsigned char) pLong[3]);

    if (written < 0 || written >= 16) {
        free(str);
        return nullptr;
    }

    return str;
}

const char *IPUtil::parseIpFormAddr(const char *str) {
    return IPUtil::uLong2IpAddr(IPUtil::ipAddr2ULong(str));
}

int IPUtil::parsePortFormAddr(const char *str) {
    const char* colonPos = strchr(str, ':');
    if (colonPos == nullptr) {
        return -1;
    }
    int port = atoi(colonPos + 1);
    if (port == 0 && colonPos[1] != '0') {
        return -1;
    }
    return port;
}

const char *IPUtil::buildFullAddr(unsigned long lHost, int port) {
    char *str = (char *) malloc(22);
    if (str == nullptr) {
        return nullptr;
    }

    int written = snprintf(str, 16, "%s:%d", IPUtil::uLong2IpAddr(lHost), port);

    if (written < 0 || written >= 22) {
        free(str);
        return nullptr;
    }

    return str;
}
