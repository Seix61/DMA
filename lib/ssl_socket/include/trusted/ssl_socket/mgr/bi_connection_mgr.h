
#ifndef LIB_TRUSTED_SSL_SOCKET_MGR_BI_CONNECTION_MGR_H
#define LIB_TRUSTED_SSL_SOCKET_MGR_BI_CONNECTION_MGR_H

#include <mutex>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <vector>
#include <ssl_socket/mgr/bi_info.h>

class BiConnectionMgr {
private:
    std::mutex dataLock;
    std::unordered_map<std::string, BiInfo> data;
    std::mutex tempLock;
    std::unordered_map<int, std::shared_ptr<SSLServerSession>> temp;
public:
    explicit BiConnectionMgr(const std::vector<std::string> &peerAddresses);

    bool registerClient(const std::string &addr, const std::shared_ptr<SSLClient> &client, const std::shared_ptr<SSLClientSession> &session);

    bool registerServer(const std::string &addr, const std::shared_ptr<SSLServerSession> &session);

    void bindSession(const std::shared_ptr<SSLClientSession> &session, int id);

    void bindSession(const std::shared_ptr<SSLServerSession> &session, int id);

    void antiRegister(const std::string &addr);

    void antiRegister(int id);

    bool isClientConnected(const std::string &addr);

    bool isClientConnected(int id);

    bool isConnected(const std::string &addr);

    bool isConnected(int id);

    std::shared_ptr<SSLServerSession> getServerSessionById(int id);

    std::shared_ptr<SSLClientSession> getClientSessionById(int id);

    int getIdBySession(const std::shared_ptr<SSLServerSession> &session);

    int getIdBySession(const std::shared_ptr<SSLClientSession> &session);

    std::string getAddrBySession(const std::shared_ptr<SSLServerSession> &session);

    std::string getAddrBySession(const std::shared_ptr<SSLClientSession> &session);

    std::unordered_set<std::shared_ptr<SSLServerSession>> getServerSessions();

    std::unordered_set<std::shared_ptr<SSLClientSession>> getClientSessions();

    std::vector<int> getIds();
};

#endif //LIB_TRUSTED_SSL_SOCKET_MGR_BI_CONNECTION_MGR_H
