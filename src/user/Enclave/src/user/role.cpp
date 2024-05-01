
#include "user/role.h"
#include "api.h"

#include <scheduler/task_scheduler.h>
#include <util/memory.h>
#include <util/ip.h>
#include <util/log.h>

UserRole::UserRole(int id, const std::vector<std::string> &peers, int peerPort) :
        id(id),
        peers(peers),
        peerPort(peerPort),
        server(std::make_shared<UserServer>(peerPort)),
        mgr(peers) {}

sgx_status_t UserRole::start() {
    if (server->create() != SGX_SUCCESS) {
        LOG_ERROR("Failed to create SSL server.");
        return SGX_ERROR_UNEXPECTED;
    }
    if (this->server->setErrorCallback(std::bind(&UserRole::serverErrorCallback, this, std::placeholders::_1, std::placeholders::_2)) != SGX_SUCCESS) {
        LOG_ERROR("Failed to set error callback.");
        return SGX_ERROR_UNEXPECTED;
    }
    if (this->server->setBeforeHandshakeHandler(std::bind(&UserRole::beforeHandshake, this, std::placeholders::_1)) != SGX_SUCCESS) {
        LOG_ERROR("Failed to set before handshake handler.");
        return SGX_ERROR_UNEXPECTED;
    }
    if (this->server->setAfterHandshakeHandler(std::bind(&UserRole::afterHandshake, this, std::placeholders::_1)) != SGX_SUCCESS) {
        LOG_ERROR("Failed to set after handshake handler.");
        return SGX_ERROR_UNEXPECTED;
    }
    for (int i = 0; i < this->peers.size(); i++) {
        TaskScheduler::executeDetachedTask([this] {
            this->serverThread();
        });
    }
    this->connectToPeersTask = std::make_shared<AsyncTask>([this] {
        for (const auto &peer: this->peers) {
            TaskScheduler::executeDetachedTask([this, peer] {
                this->clientThread(peer);
            });
        }
        TaskScheduler::executeDelayedTask(this->connectToPeersTask, 10000);
    });
    TaskScheduler::executeDelayedTask(this->connectToPeersTask, 2000);
    return SGX_SUCCESS;
}

void UserRole::serverErrorCallback(const std::shared_ptr<SSLSession> &session, int error) {
    auto nodeId = this->mgr.getIdBySession(std::static_pointer_cast<SSLServerSession>(session));
    LOG_ERROR("Server session error at node = %d with error = %d", nodeId, error);
    this->mgr.antiRegister(nodeId);
}

void UserRole::clientErrorCallback(const std::shared_ptr<SSLSession> &session, int error) {
    auto nodeId = this->mgr.getIdBySession(std::static_pointer_cast<SSLClientSession>(session));
    LOG_ERROR("Client session error at node = %d with error = %d", nodeId, error);
    this->mgr.antiRegister(nodeId);
    revoke_quote(session->getSocketFd());
}

void UserRole::beforeHandshake(int fd) {
    LOG_DEBUG("beforeHandshake %d", fd);
}

void UserRole::afterHandshake(int fd) {
    LOG_DEBUG("afterHandshake %d", fd);
}

void UserRole::serverThread() {
    while (true) {
        std::shared_ptr<SSLServerSession> session;
        if (server->accept(session) != SGX_SUCCESS) {
            LOG_ERROR("Failed to accept.");
            continue;
        }
        TaskScheduler::executeDetachedTask([this, session] {
            this->registerServerSession(session);
        });
    }
}

void UserRole::clientThread(const std::string &addr) {
    if (this->mgr.isClientConnected(addr)) {
        return;
    }
    auto serverName = IPUtil::parseIpFormAddr(addr.c_str());
    auto port = IPUtil::parsePortFormAddr(addr.c_str());
    if (port == -1) {
        port = this->peerPort;
    }
    auto client = std::make_shared<UserClient>(serverName, port);
    if (client->create() != SGX_SUCCESS) {
        LOG_ERROR("Failed to create SSL client.");
    }
    if (client->setErrorCallback(std::bind(&UserRole::clientErrorCallback, this, std::placeholders::_1, std::placeholders::_2)) != SGX_SUCCESS) {
        LOG_ERROR("Failed to set error callback.");
        return;
    }
    if (client->setBeforeHandshakeHandler(std::bind(&UserRole::beforeHandshake, this, std::placeholders::_1)) != SGX_SUCCESS) {
        LOG_ERROR("Failed to set before handshake handler.");
        return;
    }
    if (client->setAfterHandshakeHandler(std::bind(&UserRole::afterHandshake, this, std::placeholders::_1)) != SGX_SUCCESS) {
        LOG_ERROR("Failed to set after handshake handler.");
        return;
    }
    std::shared_ptr<SSLClientSession> session;
    if (client->connect(session) != SGX_SUCCESS) {
        LOG_ERROR("Failed to connect to %s:%d.", serverName, this->peerPort);
        return;
    }
    TaskScheduler::executeDetachedTask([this, addr, client, session] {
        this->registerClientSession(addr, client, session);
    });
}

void UserRole::registerServerSession(const std::shared_ptr<SSLServerSession> &session) {
    auto size = sizeof(this->id);
    auto read = Memory::makeShared<int>(size);
    if (session->read(read.get(), size) != SGX_SUCCESS) {
        return;
    }
    if (session->write(&this->id, size) != SGX_SUCCESS) {
        return;
    }
    this->mgr.registerServer(std::string(IPUtil::uLong2IpAddr(session->getIP())), session);
    this->mgr.bindSession(session, *read);
    TaskScheduler::executeDetachedTask([this, session] {
        this->handleRequest(session);
    });
}

void UserRole::registerClientSession(const std::string &addr, const std::shared_ptr<SSLClient> &client,
                                          const std::shared_ptr<SSLClientSession> &session) {
    auto size = sizeof(this->id);
    if (session->write(&this->id, size) != SGX_SUCCESS) {
        return;
    }
    auto read = Memory::makeShared<int>(size);
    if (session->read(read.get(), size) != SGX_SUCCESS) {
        return;
    }
    this->mgr.registerClient(addr, client, session);
    this->mgr.bindSession(session, *read);
    TaskScheduler::executeDetachedTask([this, session] {
        this->request(session);
    });
}

#define ClientMsg "Hello, this is client."
#define ClientMsgSize (strlen(ClientMsg) + 1)

void UserRole::handleRequest(const std::shared_ptr<SSLServerSession> &session) {
    auto read = Memory::makeShared<char>(ClientMsgSize);
    if (session->read(read.get(), ClientMsgSize) != SGX_SUCCESS) {
        return;
    }
    LOG_INFO("MsgReceived memcmp = %d", memcmp(read.get(), ClientMsg, ClientMsgSize));
}

void UserRole::request(const std::shared_ptr<SSLClientSession> &session) {
    if (session->write(ClientMsg, ClientMsgSize) != SGX_SUCCESS) {
        return;
    }
}
