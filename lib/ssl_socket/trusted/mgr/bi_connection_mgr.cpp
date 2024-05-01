
#include <ssl_socket/mgr/bi_connection_mgr.h>
#include <util/log.h>

BiConnectionMgr::BiConnectionMgr(const std::vector<std::string> &peerAddresses) {
    for (const auto &addr: peerAddresses) {
        this->data.emplace(addr, BiInfo{0, nullptr, nullptr, nullptr});
    }
}

bool BiConnectionMgr::registerClient(const std::string &addr, const std::shared_ptr<SSLClient> &client, const std::shared_ptr<SSLClientSession> &session) {
    if (addr.empty() || client == nullptr || session == nullptr) {
        return false;
    }
    std::lock_guard<std::mutex> lock(this->dataLock);
    auto it = this->data.find(addr);
    if (it == this->data.end()) {
        return false;
    }
    it->second.client = client;
    it->second.clientSession = session;
    return true;
}

bool BiConnectionMgr::registerServer(const std::string &addr, const std::shared_ptr<SSLServerSession> &session) {
    if (addr.empty() || session == nullptr) {
        return false;
    }
    std::lock_guard<std::mutex> lock(this->dataLock);
    auto it = this->data.find(addr);
    if (it == this->data.end()) {
        return false;
    }
    it->second.serverSession = session;
    return true;
}

void BiConnectionMgr::bindSession(const std::shared_ptr<SSLClientSession> &session, int id) {
    if (id == 0 || session == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(this->dataLock);
    for (auto &item : this->data) {
        if (item.second.clientSession == session) {
            item.second.id = id;
            LOG_DEBUG("Bound client session addr = %s to id = %d.", item.first.c_str(), id);
            if (item.second.serverSession == nullptr) {
                std::lock_guard<std::mutex> tLock(this->tempLock);
                if (this->temp.find(id) != this->temp.end()) {
                    item.second.serverSession = this->temp.at(id);
                    LOG_DEBUG("Bound server session addr = %s to id = %d.", item.first.c_str(), id);
                    this->temp.erase(id);
                }
            }
            return;
        }
    }
}

void BiConnectionMgr::bindSession(const std::shared_ptr<SSLServerSession> &session, int id) {
    if (id == 0 || session == nullptr) {
        return;
    }
    bool bound = false;
    {
        std::lock_guard<std::mutex> lock(this->dataLock);
        for (auto &item : this->data) {
            if (item.second.serverSession == session) {
                item.second.id = id;
                bound = true;
            }
            else if (item.second.id == id && item.second.serverSession == nullptr) {
                item.second.serverSession = session;
                bound = true;
            }
            if (bound) {
                LOG_DEBUG("Bound server session addr = %s to id = %d.", item.first.c_str(), id);
                break;
            }
        }
    }
    if (!bound) {
        std::lock_guard<std::mutex> lock(this->tempLock);
        this->temp.emplace(id, session);
    }
}

void BiConnectionMgr::antiRegister(const std::string &addr) {
    if (addr.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(this->dataLock);
    auto it = this->data.find(addr);
    if (it != this->data.end()) {
        it->second = {0, nullptr, nullptr, nullptr};
    }
}

void BiConnectionMgr::antiRegister(int id) {
    if (id == 0) {
        return;
    }
    std::lock_guard<std::mutex> lock(this->dataLock);
    for (auto &it : this->data) {
        if (it.second.id == id) {
            it.second = {0, nullptr, nullptr, nullptr};
            break;
        }
    }
}

bool BiConnectionMgr::isClientConnected(const std::string &addr) {
    if (addr.empty()) {
        return false;
    }
    std::lock_guard<std::mutex> lock(this->dataLock);
    auto it = this->data.find(addr);
    if (it == this->data.end()) {
        return false;
    }
    return it->second.clientSession != nullptr;
}

bool BiConnectionMgr::isClientConnected(int id) {
    if (id == 0) {
        return false;
    }
    std::lock_guard<std::mutex> lock(this->dataLock);
    for (const auto &it : this->data) {
        if (it.second.id == id) {
            return it.second.clientSession != nullptr;
        }
    }
    return false;
}

bool BiConnectionMgr::isConnected(const std::string &addr) {
    if (addr.empty()) {
        return false;
    }
    std::lock_guard<std::mutex> lock(this->dataLock);
    auto it = this->data.find(addr);
    if (it == this->data.end()) {
        return false;
    }
    return it->second.serverSession != nullptr && it->second.clientSession != nullptr;
}

bool BiConnectionMgr::isConnected(int id) {
    if (id == 0) {
        return false;
    }
    std::lock_guard<std::mutex> lock(this->dataLock);
    for (const auto &it : this->data) {
        if (it.second.id == id) {
            return it.second.serverSession != nullptr && it.second.clientSession != nullptr;
        }
    }
    return false;
}

std::shared_ptr<SSLServerSession> BiConnectionMgr::getServerSessionById(int id) {
    if (id == 0) {
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(this->dataLock);
    for (const auto &it : this->data) {
        if (it.second.id == id) {
            return it.second.serverSession;
        }
    }
    return nullptr;
}

std::shared_ptr<SSLClientSession> BiConnectionMgr::getClientSessionById(int id) {
    if (id == 0) {
        return nullptr;
    }
    std::lock_guard<std::mutex> lock(this->dataLock);
    for (const auto &it : this->data) {
        if (it.second.id == id) {
            return it.second.clientSession;
        }
    }
    return nullptr;
}

int BiConnectionMgr::getIdBySession(const std::shared_ptr<SSLServerSession> &session) {
    if (session == nullptr) {
        return 0;
    }
    std::lock_guard<std::mutex> lock(this->dataLock);
    for (const auto &it : this->data) {
        if (it.second.serverSession == session) {
            return it.second.id;
        }
    }
    return 0;
}

int BiConnectionMgr::getIdBySession(const std::shared_ptr<SSLClientSession> &session) {
    if (session == nullptr) {
        return 0;
    }
    std::lock_guard<std::mutex> lock(this->dataLock);
    for (const auto &it : this->data) {
        if (it.second.clientSession == session) {
            return it.second.id;
        }
    }
    return 0;
}

std::string BiConnectionMgr::getAddrBySession(const std::shared_ptr<SSLServerSession> &session) {
    if (session == nullptr) {
        return {};
    }
    std::lock_guard<std::mutex> lock(this->dataLock);
    for (const auto &it : this->data) {
        if (it.second.serverSession == session) {
            return it.first;
        }
    }
    return {};
}

std::string BiConnectionMgr::getAddrBySession(const std::shared_ptr<SSLClientSession> &session) {
    if (session == nullptr) {
        return {};
    }
    std::lock_guard<std::mutex> lock(this->dataLock);
    for (const auto &it : this->data) {
        if (it.second.clientSession == session) {
            return it.first;
        }
    }
    return {};
}

std::unordered_set<std::shared_ptr<SSLServerSession>> BiConnectionMgr::getServerSessions() {
    std::unordered_set<std::shared_ptr<SSLServerSession>> ret;
    std::lock_guard<std::mutex> lock(this->dataLock);
    for (const auto &it : this->data) {
        ret.insert(it.second.serverSession);
    }
    return ret;
}

std::unordered_set<std::shared_ptr<SSLClientSession>> BiConnectionMgr::getClientSessions() {
    std::unordered_set<std::shared_ptr<SSLClientSession>> ret;
    std::lock_guard<std::mutex> lock(this->dataLock);
    for (const auto &it : this->data) {
        ret.insert(it.second.clientSession);
    }
    return ret;
}

std::vector<int> BiConnectionMgr::getIds() {
    std::vector<int> ret;
    std::lock_guard<std::mutex> lock(this->dataLock);
    for (const auto &it : this->data) {
        ret.push_back(it.second.id);
    }
    return ret;
}
