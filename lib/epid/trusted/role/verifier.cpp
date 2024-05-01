
#include <epid/role/verifier.h>
#include <cstdlib>
#include <cstring>
#include <epid/util/rl_size.h>
#include <util/log.h>
#include <util/memory.h>

EPIDVerifier::EPIDVerifier(const GroupPubKey &pub_key) : pubKey(pub_key) {}

EPIDVerifier::~EPIDVerifier() {
    delete this->sigRl;
    delete this->privRl;
    if (this->ctx) {
        EpidVerifierDelete(&this->ctx);
    }
}

sgx_status_t EPIDVerifier::create() {
    EpidStatus ret = kEpidErr;
    do {
        if ((ret = EpidVerifierCreate(&this->pubKey, nullptr, &this->ctx)) != kEpidNoErr) {
            LOG_ERROR("Failed to EpidVerifierCreate.");
            break;
        }

        if ((ret = EpidVerifierSetHashAlg(this->ctx, kSha256)) != kEpidNoErr) {
            LOG_ERROR("Failed to EpidVerifierSetHashAlg.");
            break;
        }

        return SGX_SUCCESS;
    } while (false);

    return (sgx_status_t) ret;
}

sgx_status_t EPIDVerifier::setSigRl(SigRl *rl) {
    uint32_t rl_size = EpidGetSigRlSize(rl);
//    delete this->sigRl;
    if ((this->sigRl = (SigRl *) malloc(rl_size)) == nullptr) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    memcpy(this->sigRl, rl, rl_size);
    return (sgx_status_t) EpidVerifierSetSigRl(this->ctx, this->sigRl, rl_size);
}

sgx_status_t EPIDVerifier::setPrivRl(PrivRl *rl) {
    uint32_t rl_size = EpidGetPrivRlSize(rl);
//    delete this->privRl;
    if ((this->privRl = (PrivRl *) malloc(rl_size)) == nullptr) {
        return SGX_ERROR_OUT_OF_MEMORY;
    }
    memcpy(this->privRl, rl, rl_size);
    return (sgx_status_t) EpidVerifierSetPrivRl(this->ctx, this->privRl, rl_size);
}

sgx_status_t EPIDVerifier::setSignatureRl(const std::shared_ptr<uint8_t> &rl) {
    if (this->signatureRl.deserialize(rl)) {
        return SGX_SUCCESS;
    }
    return SGX_ERROR_UNEXPECTED;
}

sgx_status_t EPIDVerifier::verify(const EpidNonSplitSignature &sig, size_t sig_len, const void *msg, size_t msg_len) {
    auto buffer = Memory::makeShared<uint8_t>((uint8_t *)&sig, sig_len);
    if (this->signatureRl.exists(buffer, sig_len)) {
        LOG_ERROR("SignatureRl.exists returned true.");
        return SGX_ERROR_UNEXPECTED;
    }
    return (sgx_status_t) EpidVerify(this->ctx, &sig, sig_len, msg, msg_len);
}
