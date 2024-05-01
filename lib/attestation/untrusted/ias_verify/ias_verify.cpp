
#include <util/ias_verify/ias_verify.h>
#include <util/log.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <json/json.h>
#include <util/codec/base64.h>
#include <general_settings.h>

std::vector<std::string> IasVerify::quoteStatus = {
        "OK",
        "SIGNATURE_INVALID",
        "GROUP_REVOKED",
        "SIGNATURE_REVOKED",
        "KEY_REVOKED",
        "SIGRL_VERSION_MISMATCH",
        "GROUP_OUT_OF_DATE",
        "CONFIGURATION_NEEDED",
        "SW_HARDENING_NEEDED",
        "CONFIGURATION_AND_SW_HARDENING_NEEDED",
};

bool IasVerify::verifyAttestationVerificationReport(const std::string &verification_report,
                                                    const std::string &signature,
                                                    const std::string &signing_certificate,
                                                    bool &result) {
    bool ret = false;
    BIO *pemBio = nullptr, *signatureBio = nullptr;
    X509 *x509 = nullptr;
    EVP_PKEY *pubkey = nullptr;
    EVP_MD_CTX *md_ctx = nullptr;

    do {
        if (signing_certificate.find(GeneralSettings::IntelAttestationReportSigningCACert) == std::string::npos) {
            spdlog::error("Error verifying IAS certificate chain.");
            break;
        }
        if ((pemBio = BIO_new_mem_buf(signing_certificate.c_str(), -1)) == nullptr) {
            spdlog::error("Error creating BIO buffer for parsing X.509 certificate.");
            break;
        }
        if ((x509 = PEM_read_bio_X509(pemBio, nullptr, nullptr, nullptr)) == nullptr) {
            spdlog::error("Error loading X.509 certificate.");
            break;
        }
        if ((pubkey = X509_get_pubkey(x509)) == nullptr) {
            spdlog::error("Error extracting public key from X.509 certificate.");
            break;
        }
        if ((signatureBio = BIO_new_mem_buf(signature.c_str(), -1)) == nullptr) {
            spdlog::error("Error creating BIO buffer for parsing signature.");
            break;
        }
        std::string decodedSignature = Codec::Base64::decode(signature);
        // Verify the signature
        if ((md_ctx = EVP_MD_CTX_new()) == nullptr) {
            spdlog::error("Error creating EVP_MD CTX.");
            break;
        }
        EVP_MD_CTX_init(md_ctx);
        EVP_VerifyInit(md_ctx, EVP_sha256());
        EVP_VerifyUpdate(md_ctx, (const void *) verification_report.c_str(), verification_report.size());
        result = (EVP_VerifyFinal(md_ctx, (const unsigned char *) decodedSignature.c_str(), decodedSignature.size(),
                                  pubkey) == 1);

        ret = true;
    } while (false);

    if (md_ctx) {
        EVP_MD_CTX_free(md_ctx);
    }
    if (signatureBio) {
        BIO_free_all(signatureBio);
    }
    if (pubkey) {
        EVP_PKEY_free(pubkey);
    }
    if (x509) {
        X509_free(x509);
    }
    if (pemBio) {
        BIO_free(pemBio);
    }

    return ret;
}

void IasVerify::parseQuoteFromVerificationReport(const std::string &verification_report,
                                                 std::shared_ptr<sgx_quote_t> &result, size_t &quote_size) {
    Json::Value verificationReport;
    Json::Reader reader;
    reader.parse(verification_report, verificationReport);
    std::string isvEnclaveQuoteBody = Codec::Base64::decode(verificationReport["isvEnclaveQuoteBody"].asString());
    quote_size = isvEnclaveQuoteBody.length();
    result = std::make_shared<sgx_quote_t>();
    memcpy(result.get(), isvEnclaveQuoteBody.c_str(), quote_size + 1);
}

void IasVerify::parseNonceFromVerificationReport(const std::string &verification_report,
                                      std::string &nonce) {
    Json::Value verificationReport;
    Json::Reader reader;
    reader.parse(verification_report, verificationReport);
    nonce = Codec::Base64::decode(verificationReport["nonce"].asString());
}

void IasVerify::parseQuoteStatusFromVerificationReport(const std::string &verification_report, uint32_t &status) {
    Json::Value verificationReport;
    Json::Reader reader;
    reader.parse(verification_report, verificationReport);
    std::string qs = verificationReport["isvEnclaveQuoteStatus"].asString();
    for (int i = 0; i < IasVerify::quoteStatus.size(); i++) {
        if (IasVerify::quoteStatus[i] == qs) {
            status = i;
            return;
        }
    }
    status = -1;
}
