
#ifndef LIB_TRUSTED_CONSENSUS_2_CONSENSUS_H
#define LIB_TRUSTED_CONSENSUS_2_CONSENSUS_H

#include <memory>
#include <map>
#include <mutex>
#include <vector>
#include <consensus/2/log_entry.h>

class Consensus2 {
protected:
    int id;
    size_t peerCount;
private:
    std::vector<int> nodes;
    size_t totalCount;
    size_t quorumCount;
    int resendTimeout;
    int tryRecoverTimeout;
    std::map<int, std::unique_ptr<std::mutex>> logLocks;
    std::map<int, int> logIndexes;
    std::map<int, std::map<int, LogEntry>> logs;
private:
    void newLogEntry(int nodeId, int logId, size_t size, const std::shared_ptr<char> &buffer);

    void commitLog(int nodeId, int logId);

    void tryRecover(int nodeId, int logId);

protected:
    explicit Consensus2(int id, size_t peerCount);

    void dumpLog();

    void registerPeer(int nodeId);

    void propose(size_t size, const std::shared_ptr<char> &buffer);

    virtual void proposeCallback(size_t size, const std::shared_ptr<char> &buffer) = 0;

    void recover();

    void handleAcceptMessage(int fromNodeId, int logId, size_t size, const std::shared_ptr<char> &buffer);

    void handleAcceptReplyMessage(int fromNodeId, int logId);

    void handleCommitMessage(int fromNodeId, int logId, size_t size, const std::shared_ptr<char> &buffer);

    void handleCommitReplyMessage(int fromNodeId, int logId);

    void handleTryAcceptMessage(int fromNodeId, int nodeId, int logId, size_t size, const std::shared_ptr<char> &buffer);

    void handleTryAcceptReplyMessage(int fromNodeId, int nodeId, int logId);

    void handleTryCommitMessage(int fromNodeId, int nodeId, int logId, size_t size, const std::shared_ptr<char> &buffer);

    void handleTryCommitReplyMessage(int fromNodeId, int nodeId, int logId);

    void handleRecoverMessage(int fromNodeId);

    void handleRecoverReplyMessage(const std::map<int, int> &idIndex);

    void handlePrepareMessage(int fromNodeId, int nodeId, int logId);

    void handlePrepareReplyMessage(int nodeId, int logId, size_t size, const std::shared_ptr<char> &buffer);

    virtual void sendAcceptMessage(int logId, size_t size, const std::shared_ptr<char> &buffer) = 0;

    virtual void sendAcceptReplyMessage(int toNodeId, int logId) = 0;

    virtual void sendCommitMessage(int logId, size_t size, const std::shared_ptr<char> &buffer) = 0;

    virtual void sendCommitReplyMessage(int toNodeId, int logId) = 0;

    virtual void sendTryAcceptMessage(int nodeId, int logId, size_t size, const std::shared_ptr<char> &buffer) = 0;

    virtual void sendTryAcceptReplyMessage(int toNodeId, int nodeId, int logId) = 0;

    virtual void sendTryCommitMessage(int nodeId, int logId, size_t size, const std::shared_ptr<char> &buffer) = 0;

    virtual void sendTryCommitReplyMessage(int toNodeId, int nodeId, int logId) = 0;

    virtual void sendRecoverMessage() = 0;

    virtual void sendRecoverReplyMessage(int toNodeId, const std::map<int, int> &idIndex) = 0;

    virtual void sendPrepareMessage(int nodeId, int logId) = 0;

    virtual void sendPrepareReplyMessage(int toNodeId, int nodeId, int logId, size_t size, const std::shared_ptr<char> &buffer) = 0;
};

#endif //LIB_TRUSTED_CONSENSUS_2_CONSENSUS_H
