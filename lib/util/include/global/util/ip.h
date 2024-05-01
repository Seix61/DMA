
#ifndef LIB_UTIL_IP_H
#define LIB_UTIL_IP_H

class IPUtil {
public:
    static unsigned long ipAddr2ULong(const char *str);

    static char *uLong2IpAddr(unsigned long lHost);

    static const char * parseIpFormAddr(const char *str);

    static int parsePortFormAddr(const char *str);

    static const char* buildFullAddr(unsigned long lHost, int port);
};

#endif //LIB_UTIL_IP_H
