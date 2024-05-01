
#ifndef USER_ENCLAVE_API_H
#define USER_ENCLAVE_API_H

#include <memory>
#include <attestation/dma_quote.h>

void create_quote(const unsigned char *reportData, size_t reportDataSize, std::shared_ptr<dma_quote> &quote, size_t &quoteSize);

void verify_quote(const std::shared_ptr<dma_quote> &quote, size_t quoteSize, bool &pass);

struct EvidenceStoreItem {
    std::shared_ptr<uint8_t> buffer;
    size_t size;
};

void bind_quote(int key, const uint8_t evidence[], size_t evidence_size);

void revoke_quote(int key);

#endif //USER_ENCLAVE_API_H
