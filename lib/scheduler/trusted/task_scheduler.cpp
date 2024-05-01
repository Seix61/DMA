
#include <scheduler_t.h>
#include <scheduler/task_scheduler.h>
#include <util/log.h>
#include <map>
#include <mutex>

extern std::map<uint64_t, std::function<void()>> global_async_task_pool;
extern std::mutex global_async_task_pool_lock;

void _async_task_scheduler_callback(std::shared_ptr<AsyncTask> &task) {
    task->execute();
}

void TaskScheduler::executeDelayedTask(const std::shared_ptr<AsyncTask> &task, uint32_t milliseconds) {
    if (task == nullptr) {
        return;
    }

    task->reset();

    {
        std::lock_guard<std::mutex> lock(global_async_task_pool_lock);
        global_async_task_pool[task->getId()] = std::bind(&_async_task_scheduler_callback, task);
    }
    ocall_delayed_task_schedule(task->getId(), milliseconds);
}

void TaskScheduler::executeDelayedTask(const std::function<void()> &executor, uint32_t milliseconds) {
    return executeDelayedTask(std::make_shared<AsyncTask>(executor), milliseconds);
}

void TaskScheduler::cancelDelayedTask(const std::shared_ptr<AsyncTask> &task) {
    if (task == nullptr) {
        return;
    }

    task->cancel();

    std::lock_guard<std::mutex> lock(global_async_task_pool_lock);
    global_async_task_pool.erase(task->getId());
}

void TaskScheduler::executeDetachedTask(const std::shared_ptr<AsyncTask> &task) {
    if (task == nullptr) {
        return;
    }

    task->reset();

    {
        std::lock_guard<std::mutex> lock(global_async_task_pool_lock);
        global_async_task_pool[task->getId()] = std::bind(&_async_task_scheduler_callback, task);
    }
    ocall_detached_task_schedule(task->getId());
}

void TaskScheduler::executeDetachedTask(const std::function<void()> &executor) {
    return executeDetachedTask(std::make_shared<AsyncTask>(executor));
}
