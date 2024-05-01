
#include "scheduler_u.h"

#include <sgx_eid.h>
#include <sgx_error.h>
#include <chrono>
#include <thread>
#include <util/log.h>

extern sgx_enclave_id_t global_enclave_id;

void u_sleep(uint32_t milliseconds) {
    std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
}

void ocall_delayed_task_schedule(uint64_t taskId, uint32_t milliseconds) {
    std::thread task([taskId, milliseconds] {
        u_sleep(milliseconds);
        sgx_status_t ret;
        if ((ret = ecall_async_task_callback(global_enclave_id, taskId)) != SGX_SUCCESS) {
            spdlog::error("DelayedTask Id {} can not callback. Error is {0X:X}", taskId, ret);
        }
    });
    task.detach();
}

void ocall_detached_task_schedule(uint64_t taskId) {
    std::thread task([taskId] {
        sgx_status_t ret;
        if ((ret = ecall_async_task_callback(global_enclave_id, taskId)) != SGX_SUCCESS) {
            spdlog::error("DetachedTask Id {} can not callback. Error is {0X:X}", taskId, ret);
        }
    });
    task.detach();
}