
#ifndef LIB_TRUSTED_SCHEDULER_DELAYED_TASK_H
#define LIB_TRUSTED_SCHEDULER_DELAYED_TASK_H

#include <atomic>
#include <functional>

class AsyncTask {
private:
    static uint64_t total;
    uint64_t id;
    std::atomic<bool> cancelled;
    std::function<void()> executor;
public:
    explicit AsyncTask(std::function<void()> executor);

    virtual ~AsyncTask();

    uint64_t getId() const;

    void execute();

    void cancel();

    void reset();
};

#endif //LIB_TRUSTED_SCHEDULER_DELAYED_TASK_H
