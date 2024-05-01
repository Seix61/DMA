
#include "attestation_u.h"

#include <sgx_error.h>
#include <sgx_quote.h>
#include <cstdio>
#include <cstring>
#include <map>
#include <mutex>
#include <attestation/ias_client/ias_client.h>

std::map<uint64_t, std::string> global_ias_buffer;
uint64_t global_ias_buffer_count = 0;
std::mutex global_ias_buffer_lock;

sgx_status_t u_ias_buffer_get(uint64_t buffer_id, char *buffer, size_t buffer_size) {
    if (buffer_id <= 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    std::map<uint64_t, std::string>::iterator iterator;

    {
        std::lock_guard<std::mutex> lock(global_ias_buffer_lock);
        iterator = global_ias_buffer.find(buffer_id);
    }

    if (iterator != global_ias_buffer.end()) {
        if (buffer_size < iterator->second.size()) {
            return SGX_ERROR_INVALID_PARAMETER;
        }
        const char *got = iterator->second.c_str();
        memcpy(buffer, got, iterator->second.size());
    }

    return SGX_SUCCESS;
}

sgx_status_t u_ias_retrieve_sig_rl(uint8_t gid[4], size_t *sig_rl_size, uint64_t *buffer_id) {
    auto ias = std::make_shared<IasClient>();
    std::string sig_rl_str;
    if (!ias->retrieveSigRL(gid, sig_rl_str)) {
        return SGX_ERROR_UNEXPECTED;
    }
    size_t size = sig_rl_str.size();
    memcpy(sig_rl_size, &size, sizeof(size_t));

    uint64_t id;
    if (size > 0) {
        std::lock_guard<std::mutex> lock(global_ias_buffer_lock);
        id = ++global_ias_buffer_count;
        global_ias_buffer[id] = sig_rl_str;
        memcpy(buffer_id, &id, sizeof(uint64_t));
    } else {
        id = -1;
        memcpy(buffer_id, &id, sizeof(uint64_t));
    }

    return SGX_SUCCESS;
}

sgx_status_t u_ias_verify_attestation_evidence(const sgx_quote_t *p_quote, size_t quote_size,
                                               const char *p_nonce, size_t nonce_size,
                                               size_t *body_size, uint64_t *body_buffer_id,
                                               size_t *signature_size, uint64_t *signature_buffer_id,
                                               size_t *certificate_size, uint64_t *certificate_buffer_id) {
    if (p_quote == nullptr || quote_size <= 0) {
        return SGX_ERROR_INVALID_PARAMETER;
    }

    auto ias = std::make_shared<IasClient>();

    std::string quote = std::string((const char *) p_quote, quote_size);
    std::string nonce;
    if (p_nonce != nullptr && nonce_size > 0) {
        nonce = std::string((const char *) p_nonce, nonce_size);
    }

    std::string verification_report;
    std::string signature;
    std::string signing_certificate;

    if (!ias->verifyAttestationEvidence(quote, "", nonce, verification_report, signature, signing_certificate)) {
        return SGX_ERROR_UNEXPECTED;
    }

    size_t size;
    uint64_t id;

    std::lock_guard<std::mutex> lock(global_ias_buffer_lock);
    size = verification_report.size();
    memcpy(body_size, &size, sizeof(size_t));
    if (!verification_report.empty()) {
        id = ++global_ias_buffer_count;
        global_ias_buffer[id] = verification_report;
        memcpy(body_buffer_id, &id, sizeof(uint64_t));
    } else {
        id = -1;
        memcpy(body_buffer_id, &id, sizeof(uint64_t));
    }

    size = signature.size();
    memcpy(signature_size, &size, sizeof(size_t));
    if (!signature.empty()) {
        id = ++global_ias_buffer_count;
        global_ias_buffer[id] = signature;
        memcpy(signature_buffer_id, &id, sizeof(uint64_t));
    } else {
        id = -1;
        memcpy(signature_buffer_id, &id, sizeof(uint64_t));
    }

    size = signing_certificate.size();
    memcpy(certificate_size, &size, sizeof(size_t));
    if (!signing_certificate.empty()) {
        id = ++global_ias_buffer_count;
        global_ias_buffer[id] = signing_certificate;
        memcpy(certificate_buffer_id, &id, sizeof(uint64_t));
    } else {
        id = -1;
        memcpy(certificate_buffer_id, &id, sizeof(uint64_t));
    }

    return SGX_SUCCESS;
}