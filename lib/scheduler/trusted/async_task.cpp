
#include <utility>
#include <scheduler/async_task.h>

uint64_t AsyncTask::total = 0;

AsyncTask::AsyncTask(std::function<void()> executor) : cancelled(false), id(++total),
                                                       executor(std::move(executor)) {}

uint64_t AsyncTask::getId() const {
    return this->id;
}

void AsyncTask::execute() {
    if (!this->cancelled.load()) {
        if (this->executor) {
            this->executor();
        }
    }
}

void AsyncTask::cancel() {
    this->cancelled.store(true);
}

void AsyncTask::reset() {
    this->cancelled.store(false);
}

AsyncTask::~AsyncTask() {
    this->cancelled.store(true);
}
