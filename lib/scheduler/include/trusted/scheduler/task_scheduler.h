
#ifndef LIB_TRUSTED_SCHEDULER_TASK_SCHEDULER_H
#define LIB_TRUSTED_SCHEDULER_TASK_SCHEDULER_H

#include <scheduler/async_task.h>

class TaskScheduler {
public:
    static void executeDelayedTask(const std::shared_ptr<AsyncTask> &task, uint32_t milliseconds);

    static void executeDelayedTask(const std::function<void()> &executor, uint32_t milliseconds);

    static void cancelDelayedTask(const std::shared_ptr<AsyncTask> &task);

    static void executeDetachedTask(const std::shared_ptr<AsyncTask> &task);

    static void executeDetachedTask(const std::function<void()> &executor);
};

#endif //LIB_TRUSTED_SCHEDULER_TASK_SCHEDULER_H
