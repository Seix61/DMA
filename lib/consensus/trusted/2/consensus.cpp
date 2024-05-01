
#include <consensus/2/consensus.h>
#include <memory>
#include <sstream>
#include <scheduler/task_scheduler.h>
#include <util/log.h>

#define MAX(a, b) a > b ? a : b

Consensus2::Consensus2(int id, size_t peerCount) :
        id(id),
        peerCount(peerCount),
        totalCount(peerCount + 1),
        quorumCount((peerCount + 1) / 2),
        resendTimeout(1000),
        tryRecoverTimeout(5000) {
    this->registerPeer(this->id);
}

void Consensus2::registerPeer(int nodeId) {
    if (nodeId <= 0) {
        return;
    }
    this->nodes.push_back(nodeId);
    this->logLocks.emplace(nodeId, std::unique_ptr<std::mutex>(new std::mutex()));
    this->logIndexes[nodeId] = 0;
    this->logs.emplace(nodeId, std::map<int, LogEntry>());
}

void Consensus2::newLogEntry(int nodeId, int logId, size_t size, const std::shared_ptr<char> &buffer) {
    this->logs[nodeId][logId] = LogEntry(this->nodes, size, buffer);
    this->logs[nodeId][logId].acceptBy(this->id);
    this->logIndexes[nodeId] = MAX(this->logIndexes[nodeId], logId);
    this->logs[nodeId][logId].commitLogTask = std::make_shared<AsyncTask>([this, nodeId, logId] {
        this->commitLog(nodeId, logId);
    });
    this->logs[nodeId][logId].tryRecoverTask = std::make_shared<AsyncTask>([this, nodeId, logId] {
        this->tryRecover(nodeId, logId);
    });
}

void Consensus2::dumpLog() {
    std::stringstream ss;
    for (const auto &pair : this->logLocks) {
        ss << std::to_string(pair.first) << ": { ";
        for (const auto &item : this->logs[pair.first]) {
            ss << "(" << std::to_string(item.first) << ")[" <<
               "status: " << std::to_string(item.second.getStatus(this->id)) << " "
               "acceptedCount: " << std::to_string(item.second.acceptedCount()) << " "
               "committedCount: " << std::to_string(item.second.committedCount()) << " "
               "size: " << std::to_string(item.second.getSize())
               << "], ";
        }
        ss << " }\n";
    }
    LOG_DEBUG("\n%s", ss.str().c_str());
}

void Consensus2::propose(size_t size, const std::shared_ptr<char> &buffer) {
    if (size == 0 || buffer == nullptr) {
        LOG_WARN("propose called with empty buffer. skipped.");
        return;
    }
    std::lock_guard<std::mutex> lock(*this->logLocks[this->id]);
    int logId = this->logIndexes[this->id] + 1;
    this->newLogEntry(this->id, logId, size, buffer);
    LOG_INFO("propose at [%d][%d].", this->id, logId);
    this->logs[this->id][logId].sendAcceptTask = std::make_shared<AsyncTask>([this, logId] {
        this->sendAcceptMessage(logId, this->logs[this->id][logId].getSize(), this->logs[this->id][logId].getBuffer());
        TaskScheduler::executeDelayedTask([this, logId] {
            std::lock_guard<std::mutex> lock(*this->logLocks[this->id]);
            if (this->logs[this->id][logId].acceptedCount() < this->quorumCount) {
                TaskScheduler::executeDetachedTask(this->logs[this->id][logId].sendAcceptTask);
            }
        }, this->resendTimeout);
    });
    TaskScheduler::executeDetachedTask(this->logs[this->id][logId].sendAcceptTask);
}

void Consensus2::commitLog(int nodeId, int logId) {
    std::lock_guard<std::mutex> lock(*this->logLocks[nodeId]);
    if (!this->logs[nodeId][logId].isCommittedBy(this->id)) {
        this->logs[nodeId][logId].commitBy(this->id);
        this->proposeCallback(this->logs[nodeId][logId].getSize(), this->logs[nodeId][logId].getBuffer());
    }
}

void Consensus2::handleAcceptMessage(int fromNodeId, int logId, size_t size, const std::shared_ptr<char> &buffer) {
    if (size == 0 || buffer == nullptr) {
        LOG_WARN("handleAcceptMessage called with empty buffer from %d at [%d][%d].", fromNodeId, fromNodeId, logId);
        return;
    }
    std::lock_guard<std::mutex> lock(*this->logLocks[fromNodeId]);
    if (this->logs[fromNodeId].find(logId) == this->logs[fromNodeId].end()) {
        LOG_INFO("accept from %d at [%d][%d].", fromNodeId, fromNodeId, logId);
        this->newLogEntry(fromNodeId, logId, size, buffer);
        TaskScheduler::executeDelayedTask(this->logs[fromNodeId][logId].tryRecoverTask, tryRecoverTimeout);
    } else {
        if (size != this->logs[fromNodeId][logId].getSize() ||
            memcmp(buffer.get(), this->logs[fromNodeId][logId].getBuffer().get(), size) != 0) {
            LOG_WARN("accept rejected cause conflict from %d at [%d][%d].", fromNodeId, fromNodeId, logId);
            return;
        }
    }
    TaskScheduler::executeDetachedTask([this, fromNodeId, logId] {
        this->sendAcceptReplyMessage(fromNodeId, logId);
    });
}

void Consensus2::handleAcceptReplyMessage(int fromNodeId, int logId) {
    std::lock_guard<std::mutex> lock(*this->logLocks[this->id]);
    if (this->logs[this->id].find(logId) == this->logs[this->id].end()) {
        LOG_ERROR("handleAcceptReplyMessage called with non-exists log from %d at [%d][%d].", fromNodeId, this->id, logId);
        return;
    }
    this->logs[this->id][logId].acceptBy(fromNodeId);
    if (this->logs[this->id][logId].acceptedCount() > this->quorumCount && !this->logs[this->id][logId].sendCommitTask) {
        this->logs[this->id][logId].sendCommitTask = std::make_shared<AsyncTask>([this, logId] {
            this->sendCommitMessage(logId, this->logs[this->id][logId].getSize(), this->logs[this->id][logId].getBuffer());
            TaskScheduler::executeDelayedTask([this, logId] {
                std::lock_guard<std::mutex> lock(*this->logLocks[this->id]);
                if (this->logs[this->id][logId].committedCount() < this->totalCount) {
                    TaskScheduler::executeDetachedTask(this->logs[this->id][logId].sendCommitTask);
                }
            }, this->resendTimeout);
        });
        TaskScheduler::executeDetachedTask(this->logs[this->id][logId].sendCommitTask);
    }
}

void Consensus2::handleCommitMessage(int fromNodeId, int logId, size_t size, const std::shared_ptr<char> &buffer) {
    if (size == 0 || buffer == nullptr) {
        LOG_WARN("handleCommitMessage called with empty buffer from %d at [%d][%d].", fromNodeId, fromNodeId, logId);
        return;
    }
    std::lock_guard<std::mutex> lock(*this->logLocks[fromNodeId]);
    if (this->logs[fromNodeId].find(logId) == this->logs[fromNodeId].end()) {
        LOG_WARN("handleCommitMessage called with non-exists log from %d at [%d][%d]. Copied in phase 2.", fromNodeId, fromNodeId, logId);
        this->newLogEntry(fromNodeId, logId, size, buffer);
    } else {
        if (size != this->logs[fromNodeId][logId].getSize() ||
            memcmp(buffer.get(), this->logs[fromNodeId][logId].getBuffer().get(), size) != 0) {
            LOG_WARN("commit rejected cause conflict from %d at [%d][%d].", fromNodeId, fromNodeId, logId);
            return;
        }
    }
    TaskScheduler::cancelDelayedTask(this->logs[fromNodeId][logId].tryRecoverTask);
    TaskScheduler::executeDetachedTask([this, fromNodeId, logId] {
        this->sendCommitReplyMessage(fromNodeId, logId);
    });
    if (!this->logs[fromNodeId][logId].isCommittedBy(this->id)) {
        LOG_INFO("commit from %d at [%d][%d].", fromNodeId, fromNodeId, logId);
        TaskScheduler::executeDetachedTask(this->logs[fromNodeId][logId].commitLogTask);
    }
}

void Consensus2::handleCommitReplyMessage(int fromNodeId, int logId) {
    std::lock_guard<std::mutex> lock(*this->logLocks[this->id]);
    if (this->logs[this->id].find(logId) == this->logs[this->id].end()) {
        LOG_ERROR("handleCommitReplyMessage called with non-exists log from %d at [%d][%d].", fromNodeId, this->id, logId);
        return;
    }
    this->logs[this->id][logId].commitBy(fromNodeId);
    if (this->logs[this->id][logId].committedCount() == this->peerCount && !this->logs[this->id][logId].isCommittedBy(this->id)) {
        LOG_INFO("commit at [%d][%d].", this->id, logId);
        TaskScheduler::executeDetachedTask(this->logs[this->id][logId].commitLogTask);
    }
}

void Consensus2::tryRecover(int nodeId, int logId) {
    std::lock_guard<std::mutex> lock(*this->logLocks[nodeId]);
    if (this->logs[nodeId].find(logId) == this->logs[nodeId].end()) {
        LOG_ERROR("tryRecover called with non-exists log at [%d][%d].", nodeId, logId);
        return;
    }
    if (!this->logs[nodeId][logId].isCommittedBy(this->id)) {
        LOG_INFO("tryRecover at [%d][%d].", nodeId, logId);
        this->logs[nodeId][logId].sendTryAcceptTask = std::make_shared<AsyncTask>([this, nodeId, logId] {
            this->sendTryAcceptMessage(nodeId, logId, this->logs[nodeId][logId].getSize(), this->logs[nodeId][logId].getBuffer());
            TaskScheduler::executeDelayedTask([this, nodeId, logId] {
                std::lock_guard<std::mutex> lock(*this->logLocks[nodeId]);
                if (this->logs[nodeId][logId].acceptedCount() < this->quorumCount) {
                    TaskScheduler::executeDetachedTask(this->logs[nodeId][logId].sendTryAcceptTask);
                }
            }, this->resendTimeout);
        });
        TaskScheduler::executeDetachedTask(this->logs[nodeId][logId].sendTryAcceptTask);
    }
}

void Consensus2::handleTryAcceptMessage(int fromNodeId, int nodeId, int logId, size_t size,
                                        const std::shared_ptr<char> &buffer) {
    if (size == 0 || buffer == nullptr) {
        LOG_WARN("handleTryAcceptMessage called with empty buffer from %d at [%d][%d].", fromNodeId, nodeId, logId);
        return;
    }
    std::lock_guard<std::mutex> lock(*this->logLocks[nodeId]);
    if (this->logs[nodeId].find(logId) == this->logs[nodeId].end()) {
        LOG_INFO("tryAccept from %d at [%d][%d].", fromNodeId, nodeId, logId);
        this->newLogEntry(nodeId, logId, size, buffer);
    } else {
        if (size != this->logs[nodeId][logId].getSize() ||
            memcmp(buffer.get(), this->logs[nodeId][logId].getBuffer().get(), size) != 0) {
            LOG_WARN("tryAccept rejected cause conflict from %d at [%d][%d].", fromNodeId, nodeId, logId);
            return;
        }
    }
    TaskScheduler::executeDetachedTask([this, fromNodeId, nodeId, logId] {
        this->sendTryAcceptReplyMessage(fromNodeId, nodeId, logId);
    });
}

void Consensus2::handleTryAcceptReplyMessage(int fromNodeId, int nodeId, int logId) {
    std::lock_guard<std::mutex> lock(*this->logLocks[nodeId]);
    if (this->logs[nodeId].find(logId) == this->logs[nodeId].end()) {
        LOG_ERROR("handleTryAcceptReplyMessage called with non-exists log from %d at [%d][%d].", fromNodeId, nodeId, logId);
        return;
    }
    this->logs[nodeId][logId].acceptBy(fromNodeId);
    if (this->logs[nodeId][logId].acceptedCount() > this->quorumCount && !this->logs[nodeId][logId].sendTryCommitTask) {
        this->logs[nodeId][logId].sendTryCommitTask = std::make_shared<AsyncTask>([this, nodeId, logId] {
            this->sendTryCommitMessage(nodeId, logId, this->logs[nodeId][logId].getSize(), this->logs[nodeId][logId].getBuffer());
            TaskScheduler::executeDelayedTask([this, nodeId, logId] {
                std::lock_guard<std::mutex> lock(*this->logLocks[nodeId]);
                if (this->logs[nodeId][logId].committedCount() < this->totalCount) {
                    TaskScheduler::executeDetachedTask(this->logs[nodeId][logId].sendTryCommitTask);
                }
            }, this->resendTimeout);
        });
        TaskScheduler::executeDetachedTask(this->logs[nodeId][logId].sendTryCommitTask);
    }
}

void Consensus2::handleTryCommitMessage(int fromNodeId, int nodeId, int logId, size_t size,
                                        const std::shared_ptr<char> &buffer) {
    if (size == 0 || buffer == nullptr) {
        LOG_WARN("handleTryCommitMessage called with empty buffer from %d at [%d][%d].", fromNodeId, nodeId, logId);
        return;
    }
    std::lock_guard<std::mutex> lock(*this->logLocks[nodeId]);
    if (this->logs[nodeId].find(logId) == this->logs[nodeId].end()) {
        LOG_WARN("handleTryCommitMessage called with non-exists log from %d at [%d][%d]. Copied in phase 2.", fromNodeId, nodeId, logId);
        this->newLogEntry(nodeId, logId, size, buffer);
    } else {
        if (size != this->logs[nodeId][logId].getSize() ||
            memcmp(buffer.get(), this->logs[nodeId][logId].getBuffer().get(), size) != 0) {
            LOG_WARN("tryCommit rejected cause conflict from %d at [%d][%d].", fromNodeId, nodeId, logId);
            return;
        }
    }
    TaskScheduler::executeDetachedTask([this, fromNodeId, nodeId, logId] {
        this->sendTryCommitReplyMessage(fromNodeId, nodeId, logId);
    });
    if (!this->logs[nodeId][logId].isCommittedBy(this->id)) {
        LOG_INFO("tryCommit from %d at [%d][%d].", fromNodeId, nodeId, logId);
        TaskScheduler::executeDetachedTask(this->logs[nodeId][logId].commitLogTask);
    }
}

void Consensus2::handleTryCommitReplyMessage(int fromNodeId, int nodeId, int logId) {
    std::lock_guard<std::mutex> lock(*this->logLocks[nodeId]);
    if (this->logs[nodeId].find(logId) == this->logs[nodeId].end()) {
        LOG_ERROR("handleTryCommitReplyMessage called with non-exists log from %d at [%d][%d].", fromNodeId, nodeId, logId);
        return;
    }
    this->logs[nodeId][logId].commitBy(fromNodeId);
    if (this->logs[nodeId][logId].committedCount() == this->peerCount && !this->logs[nodeId][logId].isCommittedBy(this->id)) {
        LOG_INFO("tryCommit at [%d][%d].", nodeId, logId);
        TaskScheduler::executeDetachedTask(this->logs[nodeId][logId].commitLogTask);
    }
}

void Consensus2::recover() {
    TaskScheduler::executeDetachedTask([this] {
        this->sendRecoverMessage();
    });
}

void Consensus2::handleRecoverMessage(int fromNodeId) {
    bool hasLog = false;
    std::map<int, int> idIndex;
    for (const auto &pair : this->logIndexes) {
        std::lock_guard<std::mutex> lock(*this->logLocks[pair.first]);
        idIndex[pair.first] = pair.second;
        hasLog = hasLog || pair.second > 0;
    }
    if (hasLog) {
        TaskScheduler::executeDetachedTask([this, fromNodeId, idIndex] {
            this->sendRecoverReplyMessage(fromNodeId, idIndex);
        });
    }
}

void Consensus2::handleRecoverReplyMessage(const std::map<int, int> &idIndex) {
    for (const auto &node : idIndex) {
        int nodeId = node.first, maxLogId = node.second;
        std::lock_guard<std::mutex> lock(*this->logLocks[nodeId]);
        this->logIndexes[nodeId] = MAX(this->logIndexes[nodeId], maxLogId);
        for (int logId = 1; logId <= maxLogId; logId++) {
            if (this->logs[nodeId].find(logId) == this->logs[nodeId].end()) {
                TaskScheduler::executeDetachedTask([this, nodeId, logId] {
                    this->sendPrepareMessage(nodeId, logId);
                });
            }
        }
    }
}

void Consensus2::handlePrepareMessage(int fromNodeId, int nodeId, int logId) {
    std::lock_guard<std::mutex> lock(*this->logLocks[nodeId]);
    if (this->logs[nodeId].find(logId) != this->logs[nodeId].end() && this->logs[nodeId][logId].isCommittedBy(this->id)) {
        TaskScheduler::executeDetachedTask([this, fromNodeId, nodeId, logId] {
            this->sendPrepareReplyMessage(fromNodeId, nodeId, logId, this->logs[nodeId][logId].getSize(), this->logs[nodeId][logId].getBuffer());
        });
    } else {
        TaskScheduler::executeDetachedTask([this, fromNodeId, nodeId, logId] {
            this->sendPrepareReplyMessage(fromNodeId, nodeId, logId, 0, nullptr);
        });
    }
}

void Consensus2::handlePrepareReplyMessage(int nodeId, int logId, size_t size, const std::shared_ptr<char> &buffer) {
    if (size == 0 || buffer == nullptr) {
        return;
    }
    std::lock_guard<std::mutex> lock(*this->logLocks[nodeId]);
    if (this->logs[nodeId].find(logId) != this->logs[nodeId].end()) {
        return;
    }
    this->newLogEntry(nodeId, logId, size, buffer);
    LOG_INFO("commit at [%d][%d] due to prepare.", nodeId, logId);
    TaskScheduler::executeDetachedTask(this->logs[nodeId][logId].commitLogTask);
}
