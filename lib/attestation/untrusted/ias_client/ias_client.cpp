
#include <attestation/ias_client/ias_client.h>
#include <sstream>
#include <iomanip>
#include <util/log.h>
#include <util/codec/base64.h>
#include <util/codec/url.h>
#include <json/json.h>
#include <openssl/err.h>
#include <general_settings.h>

IasClient::IasClient() {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    this->curl = curl_easy_init();
    curl_easy_setopt(this->curl, CURLOPT_TIMEOUT, 8L);
    curl_easy_setopt(this->curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
    curl_easy_setopt(this->curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
    curl_easy_setopt(this->curl, CURLOPT_SSL_VERIFYHOST, 0);
    curl_easy_setopt(this->curl, CURLOPT_NOPROGRESS, 1L);
}

IasClient::~IasClient() {
    if (this->curl) {
        curl_easy_cleanup(this->curl);
    }
}

std::string IasClient::parseGid(const uint8_t *gid) {
    uint32_t intValue = 0;
    intValue |= (static_cast<uint32_t>(gid[0]));
    intValue |= (static_cast<uint32_t>(gid[1]) << 8);
    intValue |= (static_cast<uint32_t>(gid[2]) << 16);
    intValue |= (static_cast<uint32_t>(gid[3]) << 24);

    std::stringstream ss;
    ss << std::hex << std::setw(8) << std::setfill('0') << intValue;
    return ss.str();
}

size_t IasClient::parseResponseBody(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t totalSize;
    if ((totalSize = size * nmemb) == 0) {
        return 0;
    }

    auto *body = (ias_response_body *) userdata;
    body->content = (char *) realloc(body->content, body->size + totalSize + 1);

    if (body->content == nullptr) {
        spdlog::error("Unable to allocate extra memory.");
        return 0;
    }

    memcpy(&(body->content[body->size]), ptr, totalSize);
    body->size += totalSize;
    body->content[body->size] = 0;

    return totalSize;
}

size_t IasClient::parseResponseHeader(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t totalSize;
    if ((totalSize = size * nmemb) == 0) {
        return 0;
    }

    auto *header = (ias_response_header *) userdata;

    if (sscanf((char *) ptr, "HTTP/1.1 %d", &header->http_status) == 1) {
        return totalSize;
    }
    if (sscanf((char *) ptr, "Content-Length: %d", &header->content_length) == 1) {
        return totalSize;
    }
    if (sscanf((char *) ptr, "Request-ID: %32s", header->request_id) == 1) {
        return totalSize;
    }
    if (sscanf((char *) ptr, "X-IASReport-Signature: %512s", header->x_iasreport_signature) == 1) {
        return totalSize;
    }
    if (sscanf((char *) ptr, "X-IASReport-Signing-Certificate: %8192s", header->x_iasreport_signing_certificate) ==
        1) {
        return totalSize;
    }

    return totalSize;
}

bool IasClient::send(const std::string &url, const std::string &request_body, const curl_slist *request_headers,
                     ias_response_body *response_body, ias_response_header *response_header) {
    CURLcode res = CURLE_OK;

#ifdef LOG_VERBOSE
    spdlog::info("Url is {}", url);
#endif
    curl_easy_setopt(this->curl, CURLOPT_URL, url.c_str());

    if (request_headers) {
        curl_easy_setopt(this->curl, CURLOPT_HTTPHEADER, request_headers);
    }
    if (!request_body.empty()) {
        curl_easy_setopt(this->curl, CURLOPT_POSTFIELDS, request_body.c_str());
    }

    response_body->content = (char *) malloc(1);
    response_body->content[0] = 0;
    response_body->size = 0;

    curl_easy_setopt(this->curl, CURLOPT_HEADERFUNCTION, IasClient::parseResponseHeader);
    curl_easy_setopt(this->curl, CURLOPT_HEADERDATA, response_header);
    curl_easy_setopt(this->curl, CURLOPT_WRITEFUNCTION, IasClient::parseResponseBody);
    curl_easy_setopt(this->curl, CURLOPT_WRITEDATA, response_body);

    if ((res = curl_easy_perform(this->curl)) != CURLE_OK) {
        spdlog::error("curl_easy_perform() failed: {}.\n", curl_easy_strerror(res));
        return false;
    }

    return true;
}

bool IasClient::retrieveSigRL(const uint8_t gid[4], std::string &sig_rl) {
    curl_slist *requestHeaders = nullptr;
    requestHeaders = curl_slist_append(requestHeaders,
                                       ("Ocp-Apim-Subscription-Key: " + GeneralSettings::SubscriptionKey).c_str());

    ias_response_body responseBody{};
    ias_response_header responseHeader{};
    this->send(GeneralSettings::IntelAttestationServiceHost + "/sigrl/" + IasClient::parseGid(gid), "", requestHeaders, &responseBody, &responseHeader);

    if (responseHeader.http_status != 200) {
        spdlog::error("Retrieve SigRL returned with http_status {}", responseHeader.http_status);
        return false;
    }

    sig_rl = Codec::Base64::decode(responseBody.content);

    return true;
}

bool IasClient::verifyAttestationEvidence(const std::string &quote,
                                          const std::string &pse_manifest,
                                          const std::string &nonce,
                                          std::string &verification_report,
                                          std::string &signature,
                                          std::string &signing_certificate) {
    Json::Value json;
    if (!quote.empty()) {
        json["isvEnclaveQuote"] = Codec::Base64::encode(quote);
    }
    if (!pse_manifest.empty()) {
        json["pseManifest"] = Codec::Base64::encode(pse_manifest);
    }
    if (!nonce.empty()) {
        json["nonce"] = Codec::Base64::encode(nonce);
    }
    Json::FastWriter fastWriter;
    std::string requestBody = fastWriter.write(json);
#ifdef LOG_VERBOSE
    spdlog::debug("Ias::verifyAttestationEvidence request body: {}", requestBody);
#endif

    // Request Header
    curl_slist *requestHeaders = nullptr;
    requestHeaders = curl_slist_append(requestHeaders, "Content-Type: application/json");
    requestHeaders = curl_slist_append(requestHeaders,
                                       ("Ocp-Apim-Subscription-Key: " + GeneralSettings::SubscriptionKey).c_str());
    requestHeaders = curl_slist_append(requestHeaders, "Expect:");

    // Send
    ias_response_body responseBody{};
    ias_response_header responseHeader{};
    this->send(GeneralSettings::IntelAttestationServiceHost + "/report", requestBody, requestHeaders, &responseBody, &responseHeader);

    if (responseHeader.http_status != 200) {
        spdlog::error("Verify Attestation Evidence returned with http_status {}", responseHeader.http_status);
        return false;
    }

    verification_report = responseBody.content;
    signature = responseHeader.x_iasreport_signature;
    signing_certificate = Codec::Url::decode(responseHeader.x_iasreport_signing_certificate);

    return true;
}
