
#ifndef LIB_UNTRUSTED_ATTESTATION_IAS_CLIENT_IAS_CLIENT_H
#define LIB_UNTRUSTED_ATTESTATION_IAS_CLIENT_IAS_CLIENT_H

#include <memory>
#include <sgx_quote.h>
#include <curl/curl.h>
#include <attestation/ias_client/messages.h>

class IasClient {
private:
    CURL *curl;

    static std::string parseGid(const uint8_t gid[4]);

    static size_t parseResponseBody(void *ptr, size_t size, size_t nmemb, void *userdata);

    static size_t parseResponseHeader(void *ptr, size_t size, size_t nmemb, void *userdata);

    bool send(const std::string &url, const std::string &request_body, const curl_slist *request_headers,
              ias_response_body *response_body, ias_response_header *response_header);

public:
    IasClient();

    ~IasClient();

    bool retrieveSigRL(const uint8_t gid[4], std::string &sig_rl);

    bool verifyAttestationEvidence(const std::string &quote,
                                   const std::string &pse_manifest,
                                   const std::string &nonce,
                                   std::string &verification_report,
                                   std::string &signature,
                                   std::string &signing_certificate);
};

#endif //LIB_UNTRUSTED_ATTESTATION_IAS_CLIENT_IAS_CLIENT_H
