
#ifndef LIB_TRUSTED_ATTESTATION_DMA_QUOTE_H
#define LIB_TRUSTED_ATTESTATION_DMA_QUOTE_H

#include <sgx_report.h>

struct dma_signed_data {
    uint32_t            platform_status;
    sgx_report_body_t   report_body;
};

struct dma_quote {
    uint32_t            platform_status;
    sgx_report_body_t   report_body;
    uint32_t            signature_len;
    uint8_t             signature[];
};

#endif //LIB_TRUSTED_ATTESTATION_DMA_QUOTE_H
