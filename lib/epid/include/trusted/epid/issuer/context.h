
#ifndef LIB_TRUSTED_EPID_ISSUER_CONTEXT_H
#define LIB_TRUSTED_EPID_ISSUER_CONTEXT_H

#include <epid/types.h>
#include <common/epid2params.h>
#include <common/grouppubkey.h>

#ifdef __cplusplus
extern "C"{
#endif

typedef struct IPrivKey_ {
    GroupId gid;   ///< group ID
    FfElement *gamma;  ///< an integer between [0, p-1]
} IPrivKey_;

typedef struct IssuerCtx {
    GroupPubKey_ *pub_key;       ///< group public key
    Epid2Params_ *epid2_params;  ///< Intel(R) EPID 2.0 params
    IPrivKey_ *ipriv_key;          ///< Member private key

    BitSupplier rnd_func;  ///< Pseudo random number generation function
    void *rnd_param;       ///< Pointer to user context for rnd_func
    HashAlg hash_alg;      ///< Hash algorithm to use

    IssuerNonce ni;

    PrivRl *priv_rl;
    SigRl *sig_rl;
} IssuerCtx;

#ifdef __cplusplus
}
#endif

#endif //LIB_TRUSTED_EPID_ISSUER_CONTEXT_H
