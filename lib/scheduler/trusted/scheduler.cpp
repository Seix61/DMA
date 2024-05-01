
#include "scheduler_t.h"

#include <map>
#include <mutex>

std::map<uint64_t, std::function<void()>> global_async_task_pool;
std::mutex global_async_task_pool_lock;

void ecall_async_task_callback(uint64_t taskId) {
    std::map<uint64_t, std::function<void()>>::iterator callback;

    {
        std::lock_guard<std::mutex> lock(global_async_task_pool_lock);
        callback = global_async_task_pool.find(taskId);
    }

    if (callback != global_async_task_pool.end()) {
        callback->second();
    }
}