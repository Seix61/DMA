
#include <consensus/2/log_entry.h>

LogEntry::LogEntry() : size(0), buffer() {}

LogEntry::LogEntry(const std::vector<int> &nodes, size_t size, const std::shared_ptr<char> &buffer)
        : size(size), buffer(buffer) {
    for (const auto &node : nodes) {
        this->acceptStatus.emplace(node, false);
        this->commitStatus.emplace(node, false);
    }
}

size_t LogEntry::getSize() const {
    return size;
}

const std::shared_ptr<char> &LogEntry::getBuffer() const {
    return this->buffer;
}

LogEntryStatus LogEntry::getStatus(int nodeId) const {
    if (this->isAcceptedBy(nodeId)) {
        return Accepted;
    }
    if (this->isCommittedBy(nodeId)) {
        return Committed;
    }
    return None;
}

void LogEntry::acceptBy(int nodeId) {
    this->acceptStatus[nodeId] = true;
}

void LogEntry::commitBy(int nodeId) {
    this->commitStatus[nodeId] = true;
}

bool LogEntry::isAcceptedBy(int nodeId) const {
    return this->acceptStatus.at(nodeId);
}

bool LogEntry::isCommittedBy(int nodeId) const {
    return this->commitStatus.at(nodeId);
}

int LogEntry::acceptedCount() const {
    int count = 0;
    for (const auto &pair : this->acceptStatus) {
        if (pair.second) {
            count++;
        }
    }
    return count;
}

int LogEntry::committedCount() const {
    int count = 0;
    for (const auto &pair : this->commitStatus) {
        if (pair.second) {
            count++;
        }
    }
    return count;
}
