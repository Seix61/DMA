
#ifndef LIB_TRUSTED_EPID_ROLE_VERIFIER_H
#define LIB_TRUSTED_EPID_ROLE_VERIFIER_H

#include <epid/verifier.h>
#include <sgx_error.h>
#include <epid/sig_rl.h>

class EPIDVerifier {
private:
    VerifierCtx *ctx = nullptr;
    GroupPubKey pubKey{};
    SigRl *sigRl = nullptr;
    PrivRl *privRl = nullptr;
    SignatureRl signatureRl;
public:
    explicit EPIDVerifier(const GroupPubKey &pub_key);

    virtual ~EPIDVerifier();

    sgx_status_t create();

    sgx_status_t setSigRl(SigRl *rl);

    sgx_status_t setPrivRl(PrivRl *rl);

    sgx_status_t setSignatureRl(const std::shared_ptr<uint8_t> &rl);

    sgx_status_t verify(const EpidNonSplitSignature &sig, size_t sig_len, const void *msg, size_t msg_len);
};

#endif //LIB_TRUSTED_EPID_ROLE_VERIFIER_H
