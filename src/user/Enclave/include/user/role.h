
#ifndef USER_ENCLAVE_USER_ROLE_H
#define USER_ENCLAVE_USER_ROLE_H

#include "user/socket/server.h"
#include "user/socket/client.h"

#include <memory>
#include <vector>
#include <scheduler/async_task.h>
#include <ssl_socket/mgr/bi_connection_mgr.h>

class UserRole {
private:
    int id;
    std::vector<std::string> peers;
    int peerPort;
    std::shared_ptr<UserServer> server;
    BiConnectionMgr mgr;
    std::shared_ptr<AsyncTask> connectToPeersTask;
    std::shared_ptr<AsyncTask> clientSendTask;
private:
    void serverThread();

    void clientThread(const std::string &addr);

    void clientErrorCallback(const std::shared_ptr<SSLSession> &session, int error);

    void serverErrorCallback(const std::shared_ptr<SSLSession> &session, int error);

    void beforeHandshake(int fd);

    void afterHandshake(int fd);

    void registerServerSession(const std::shared_ptr<SSLServerSession> &session);

    void registerClientSession(const std::string &addr, const std::shared_ptr<SSLClient> &client,
                               const std::shared_ptr<SSLClientSession> &session);

    void handleRequest(const std::shared_ptr<SSLServerSession>& session);

    void request(const std::shared_ptr<SSLClientSession>& session);

protected:
    explicit UserRole(int id, const std::vector<std::string> &peers, int peerPort);

    sgx_status_t start();
};

#endif //USER_ENCLAVE_USER_ROLE_H
