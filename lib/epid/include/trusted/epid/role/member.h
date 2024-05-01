
#ifndef LIB_TRUSTED_EPID_ROLE_MEMBER_H
#define LIB_TRUSTED_EPID_ROLE_MEMBER_H

#include <epid/types.h>
#include <epid/member/api.h>
#include <sgx_error.h>

class EPIDMember {
private:
    MemberCtx *ctx = nullptr;
    MemberParams params{};
    GroupPubKey pubKey;
    SigRl *sigRl = nullptr;
public:
    explicit EPIDMember(const GroupPubKey &pub_key);

    virtual ~EPIDMember();

    sgx_status_t create();

    sgx_status_t exportPrivF(FpElemStr &f) const;

    sgx_status_t createJoinRequest(const IssuerNonce &nonce, NoneSplitJoinRequest &join_req);

    sgx_status_t provision(const MembershipCredential &member_cred);

    sgx_status_t setSigRl(SigRl *rl);

    sgx_status_t startUp();

    sgx_status_t getSigSize(size_t &size);

    sgx_status_t
    sign(void const *msg, size_t msg_len, void const *basename, size_t basename_len, EpidNonSplitSignature &signature,
         size_t signature_len);
};

#endif //LIB_TRUSTED_EPID_ROLE_MEMBER_H
