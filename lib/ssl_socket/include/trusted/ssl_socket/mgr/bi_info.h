
#ifndef LIB_TRUSTED_SSL_SOCKET_MGR_BI_INFO_H
#define LIB_TRUSTED_SSL_SOCKET_MGR_BI_INFO_H

#include <ssl_socket/server/ssl_server_session.h>
#include <ssl_socket/client/ssl_client_session.h>
#include <ssl_socket/client/ssl_client.h>

struct BiInfo {
    int id;
    std::shared_ptr<SSLServerSession> serverSession;
    std::shared_ptr<SSLClient> client;
    std::shared_ptr<SSLClientSession> clientSession;
};

#endif //LIB_TRUSTED_SSL_SOCKET_MGR_BI_INFO_H
