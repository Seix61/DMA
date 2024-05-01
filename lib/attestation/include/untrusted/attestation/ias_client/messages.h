
#ifndef LIB_UNTRUSTED_ATTESTATION_IAS_CLIENT_MESSAGES_H
#define LIB_UNTRUSTED_ATTESTATION_IAS_CLIENT_MESSAGES_H

#include <string>

#define REQUEST_ID_MAX_LEN 32
#define X_IASREPORT_SIGNATURE_MAX_LEN 512
#define X_IASREPORT_SIGNING_CERTIFICATE_MAX_LEN 8192

struct ias_response_header {
    int http_status;
    int content_length;
    char request_id[REQUEST_ID_MAX_LEN + 1];
    char x_iasreport_signature[X_IASREPORT_SIGNATURE_MAX_LEN + 1];
    char x_iasreport_signing_certificate[X_IASREPORT_SIGNING_CERTIFICATE_MAX_LEN + 1];
};

struct ias_response_body {
    char *content;
    size_t size;
};

#endif //LIB_UNTRUSTED_ATTESTATION_IAS_CLIENT_MESSAGES_H
