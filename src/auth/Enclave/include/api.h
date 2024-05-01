
#ifndef AUTH_ENCLAVE_API_H
#define AUTH_ENCLAVE_API_H

#include <cstdint>

void record_platform_status(int socketFd, uint32_t status);

uint32_t get_platform_status(int socketFd);

#endif //AUTH_ENCLAVE_API_H
