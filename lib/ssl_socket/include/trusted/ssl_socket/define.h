
#ifndef LIB_TRUSTED_SSL_SOCKET_PEER_DEFINE_H
#define LIB_TRUSTED_SSL_SOCKET_PEER_DEFINE_H

#include <libcxx/map>
#include <libcxx/string>

#define CLIENT_PAYLOAD "GET / HTTP/1.0\n\n"
#define SERVER_PAYLOAD                                   \
    "HTTP/1.0 200 OK\nContent-Type: text/html\n\n" \
    "<h2>mbed TLS Test Server</h2>\n"                  \
    "<p>Successful connection : </p>\n"                \
    "A message from TLS server inside enclave\n"
#define CLIENT_PAYLOAD_SIZE sizeof(CLIENT_PAYLOAD)
#define SERVER_PAYLOAD_SIZE sizeof(SERVER_PAYLOAD)

#define OID_FOR_QUOTE_STRING "1.2.840.113741.1.13.1"

#endif //LIB_TRUSTED_SSL_SOCKET_PEER_DEFINE_H
