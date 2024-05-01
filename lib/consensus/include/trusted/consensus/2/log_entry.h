
#ifndef LIB_TRUSTED_CONSENSUS_2_LOG_ENTRY_H
#define LIB_TRUSTED_CONSENSUS_2_LOG_ENTRY_H

#include <map>
#include <vector>
#include <consensus/2/log_entry_status.h>
#include <scheduler/task_scheduler.h>

class LogEntry {
private:
    size_t size;
    std::shared_ptr<char> buffer;

    std::map<int, bool> acceptStatus;
    std::map<int, bool> commitStatus;
public:
    std::shared_ptr<AsyncTask> sendAcceptTask = nullptr;
    std::shared_ptr<AsyncTask> sendCommitTask = nullptr;
    std::shared_ptr<AsyncTask> sendTryAcceptTask = nullptr;
    std::shared_ptr<AsyncTask> sendTryCommitTask = nullptr;
    std::shared_ptr<AsyncTask> commitLogTask = nullptr;
    std::shared_ptr<AsyncTask> tryRecoverTask = nullptr;
public:
    LogEntry();

    LogEntry(const std::vector<int> &nodes, size_t size, const std::shared_ptr<char> &buffer);

    size_t getSize() const;

    const std::shared_ptr<char> &getBuffer() const;

    LogEntryStatus getStatus(int nodeId) const;

    void acceptBy(int nodeId);

    void commitBy(int nodeId);

    bool isAcceptedBy(int nodeId) const;

    bool isCommittedBy(int nodeId) const;

    int acceptedCount() const;

    int committedCount() const;
};

#endif //LIB_TRUSTED_CONSENSUS_2_LOG_ENTRY_H
