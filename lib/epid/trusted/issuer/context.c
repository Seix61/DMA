
#include <epid/issuer/context.h>
#include <epid/issuer/api.h>
#include <ippmath/memory.h>
#include <common/sigrlvalid.h>

#define BREAK_ON_EPID_ERROR(ret) \
  if (kEpidNoErr != (ret)) {     \
    break;                       \
  }

void DeleteIssueKey(IPrivKey_ **ipriv_key) {
    if (ipriv_key) {
        if (*ipriv_key) {
            DeleteFfElement(&((*ipriv_key)->gamma));
        }
        SAFE_FREE(*ipriv_key);
    }
}

EpidStatus CreateIssueKey(FiniteField *Fp, BitSupplier rnd_func, void *rnd_func_param, IPrivKey_ **ipriv_key) {
    EpidStatus result = kEpidErr;
    IPrivKey_ *ipriv_key_ = NULL;

    // check parameters
    if (!Fp || !ipriv_key) {
        return kEpidBadArgErr;
    }

    do {
        ipriv_key_ = SAFE_ALLOC(sizeof(IPrivKey_))
        if (!ipriv_key_) {
            result = kEpidMemAllocErr;
            break;
        }

        result = NewFfElement(Fp, &ipriv_key_->gamma);
        BREAK_ON_EPID_ERROR(result);
        static const BigNumStr one = {{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}};
        result = FfGetRandom(Fp, &one, rnd_func, rnd_func_param, ipriv_key_->gamma);
        BREAK_ON_EPID_ERROR(result);

        rnd_func((unsigned int *) &ipriv_key_->gid, sizeof(ipriv_key_->gid) * 8, NULL);
        ipriv_key_->gid.data[0] = 0;
        ipriv_key_->gid.data[1] = kSha256;

        *ipriv_key = ipriv_key_;
        result = kEpidNoErr;
    } while (0);

    if (kEpidNoErr != result) {
        DeleteIssueKey(&ipriv_key_);
    }

    return (result);
}

EpidStatus
GenerateGroupPubKey(Epid2Params_ *epid2_params, IPrivKey_ *ipriv_key, BitSupplier rnd_func, void *rnd_func_param,
                    GroupPubKey_ **pub_key) {
    EpidStatus result = kEpidErr;
    GroupPubKey_ *pubkey = NULL;
    if (!epid2_params || !ipriv_key || !rnd_func || !pub_key) {
        return kEpidBadArgErr;
    }

    if (!rnd_func_param) {};

    EcGroup *G1 = epid2_params->G1;
    EcGroup *G2 = epid2_params->G2;
    FiniteField *Fp = epid2_params->Fp;
    EcPoint *g2 = epid2_params->g2;

    do {
        pubkey = SAFE_ALLOC(sizeof(GroupPubKey_));
        if (!pubkey) {
            result = kEpidMemAllocErr;
            break;
        }
        result = NewEcPoint(G1, &pubkey->h1);
        BREAK_ON_EPID_ERROR(result);
        result = EcGetRandom(G1, rnd_func, &rnd_func, pubkey->h1);
        BREAK_ON_EPID_ERROR(result);
        result = NewEcPoint(G1, &pubkey->h2);
        BREAK_ON_EPID_ERROR(result);
        result = EcGetRandom(G1, rnd_func, &rnd_func, pubkey->h2);
        BREAK_ON_EPID_ERROR(result);

        result = NewEcPoint(G2, &pubkey->w);
        BREAK_ON_EPID_ERROR(result);
        BigNumStr gamma_str = {0};
        result = WriteFfElement(Fp, ipriv_key->gamma, &gamma_str, sizeof(gamma_str));
        BREAK_ON_EPID_ERROR(result);
        result = EcExp(G2, g2, &gamma_str, pubkey->w);
        BREAK_ON_EPID_ERROR(result);

        pubkey->gid = ipriv_key->gid;

        *pub_key = pubkey;
        result = kEpidNoErr;
    } while (0);

    if (kEpidNoErr != result && pubkey) {
        DeleteEcPoint(&pubkey->w);
        DeleteEcPoint(&pubkey->h2);
        DeleteEcPoint(&pubkey->h1);
        SAFE_FREE(pubkey);
    }
    return result;
}

EpidStatus EpidIssuerCreate(BitSupplier rnd_func, void *rnd_param, IssuerCtx **ctx) {
    EpidStatus result = kEpidErr;
    IssuerCtx *issuer_ctx = NULL;

    if (!rnd_func || !ctx) {
        return kEpidBadArgErr;
    }

    // Allocate memory for IssuerCtx
    issuer_ctx = SAFE_ALLOC(sizeof(IssuerCtx))
    if (!issuer_ctx) {
        return kEpidMemAllocErr;
    }

    issuer_ctx->priv_rl = SAFE_ALLOC(sizeof(PrivRl) - sizeof(FpElemStr));
    if (!issuer_ctx->priv_rl) {
        SAFE_FREE(issuer_ctx);
        return kEpidMemAllocErr;
    }

    issuer_ctx->sig_rl = SAFE_ALLOC(sizeof(SigRl) - sizeof(SigRlEntry));
    if (!issuer_ctx->sig_rl) {
        SAFE_FREE(issuer_ctx->priv_rl);
        SAFE_FREE(issuer_ctx);
        return kEpidMemAllocErr;
    }

    do {
        issuer_ctx->hash_alg = kSha256;
        // Internal representation of Epid2Params
        result = CreateEpid2Params(&issuer_ctx->epid2_params);
        BREAK_ON_EPID_ERROR(result);
        // Internal representation of Issuer Issue Key
        result = CreateIssueKey(issuer_ctx->epid2_params->Fp, rnd_func, rnd_param, &issuer_ctx->ipriv_key);
        BREAK_ON_EPID_ERROR(result);

        // Internal representation of Group Pub Key
        result = GenerateGroupPubKey(issuer_ctx->epid2_params, issuer_ctx->ipriv_key, rnd_func, rnd_param,
                                     &issuer_ctx->pub_key);
        BREAK_ON_EPID_ERROR(result);

        issuer_ctx->rnd_func = rnd_func;
        issuer_ctx->rnd_param = rnd_param;

        OctStr32 octstr32_0 = {{0x00, 0x00, 0x00, 0x00}};
        issuer_ctx->priv_rl->gid = issuer_ctx->ipriv_key->gid;
        issuer_ctx->priv_rl->version = octstr32_0;
        issuer_ctx->priv_rl->n1 = octstr32_0;

        issuer_ctx->sig_rl->gid = issuer_ctx->ipriv_key->gid;
        issuer_ctx->sig_rl->version = octstr32_0;
        issuer_ctx->sig_rl->n2 = octstr32_0;

        *ctx = issuer_ctx;
        result = kEpidNoErr;
    } while (0);

    if (kEpidNoErr != result) {
        EpidIssuerDelete(&issuer_ctx);
    }

    return result;
}

EpidStatus EpidImportGroupPubKey(IssuerCtx *ctx, const GroupPubKey *ext_pub_key) {
    EpidStatus result = kEpidErr;
    GroupPubKey_ *pubkey = NULL;
    if (!ext_pub_key || !ctx) {
        return kEpidBadArgErr;
    }

    EcGroup *G1 = ctx->epid2_params->G1;
    EcGroup *G2 = ctx->epid2_params->G2;

    do {
        pubkey = SAFE_ALLOC(sizeof(GroupPubKey_));
        if (!pubkey) {
            result = kEpidMemAllocErr;
            break;
        }
        result = NewEcPoint(G1, &pubkey->h1);
        BREAK_ON_EPID_ERROR(result);
        result = NewEcPoint(G1, &pubkey->h2);
        BREAK_ON_EPID_ERROR(result);
        result = NewEcPoint(G2, &pubkey->w);
        BREAK_ON_EPID_ERROR(result);

        result = ReadEcPoint(G1, &ext_pub_key->h1, sizeof(G1ElemStr), pubkey->h1);
        BREAK_ON_EPID_ERROR(result);
        result = ReadEcPoint(G1, &ext_pub_key->h2, sizeof(G1ElemStr), pubkey->h2);
        BREAK_ON_EPID_ERROR(result);
        result = ReadEcPoint(G2, &ext_pub_key->w, sizeof(G2ElemStr), pubkey->w);
        BREAK_ON_EPID_ERROR(result);

        pubkey->gid = ext_pub_key->gid;

        ctx->pub_key = pubkey;
        result = kEpidNoErr;
    } while (0);
    if (kEpidNoErr != result && pubkey) {
        DeleteEcPoint(&pubkey->w);
        DeleteEcPoint(&pubkey->h2);
        DeleteEcPoint(&pubkey->h1);
        SAFE_FREE(pubkey);
    }
    return result;
}

EpidStatus EpidImportIssueKey(IssuerCtx *ctx, const IPrivKey *ext_ipriv_key) {
    EpidStatus result = kEpidErr;
    IPrivKey_ *ipriv_key_ = NULL;

    // check parameters
    if (!ext_ipriv_key || !ctx) {
        return kEpidBadArgErr;
    }


    FiniteField *Fp = ctx->epid2_params->Fp;

    do {
        ipriv_key_ = SAFE_ALLOC(sizeof(IPrivKey_))
        if (!ipriv_key_) {
            result = kEpidMemAllocErr;
            break;
        }

        result = NewFfElement(Fp, &ipriv_key_->gamma);
        BREAK_ON_EPID_ERROR(result);
        result = ReadFfElement(Fp, &ext_ipriv_key->gamma, sizeof(FpElemStr), ipriv_key_->gamma);
        BREAK_ON_EPID_ERROR(result);
        ipriv_key_->gid = ext_ipriv_key->gid;

        ctx->ipriv_key = ipriv_key_;
        result = kEpidNoErr;
    } while (0);

    if (kEpidNoErr != result) {
        DeleteIssueKey(&ipriv_key_);
    }

    return (result);
}

// WARNING: priv_rl and sig_rl should be imported manually
EpidStatus
EpidIssuerImport(const GroupPubKey *pub_key, const IPrivKey *ipriv_key, BitSupplier rnd_func, void *rnd_param,
                 IssuerCtx **ctx) {
    EpidStatus result = kEpidErr;
    IssuerCtx *issuer_ctx = NULL;

    if (!rnd_func || !ctx) {
        return kEpidBadArgErr;
    }

    // Allocate memory for IssuerCtx
    issuer_ctx = SAFE_ALLOC(sizeof(IssuerCtx))
    if (!issuer_ctx) {
        return kEpidMemAllocErr;
    }

    issuer_ctx->priv_rl = SAFE_ALLOC(sizeof(PrivRl) - sizeof(FpElemStr));
    if (!issuer_ctx->priv_rl) {
        SAFE_FREE(issuer_ctx);
        return kEpidMemAllocErr;
    }

    issuer_ctx->sig_rl = SAFE_ALLOC(sizeof(SigRl) - sizeof(SigRlEntry));
    if (!issuer_ctx->sig_rl) {
        SAFE_FREE(issuer_ctx->priv_rl);
        SAFE_FREE(issuer_ctx);
        return kEpidMemAllocErr;
    }

    do {
        issuer_ctx->hash_alg = kSha256;
        // Internal representation of Epid2Params
        result = CreateEpid2Params(&issuer_ctx->epid2_params);
        BREAK_ON_EPID_ERROR(result);
        // Internal representation of Issuer Issue Key
        result = EpidImportIssueKey(issuer_ctx, ipriv_key);
        BREAK_ON_EPID_ERROR(result);

        // Internal representation of Group Pub Key
        result = EpidImportGroupPubKey(issuer_ctx, pub_key);
        BREAK_ON_EPID_ERROR(result);

        issuer_ctx->rnd_func = rnd_func;
        issuer_ctx->rnd_param = rnd_param;

        OctStr32 octstr32_0 = {{0x00, 0x00, 0x00, 0x00}};
        issuer_ctx->priv_rl->gid = issuer_ctx->ipriv_key->gid;
        issuer_ctx->priv_rl->version = octstr32_0;
        issuer_ctx->priv_rl->n1 = octstr32_0;

        issuer_ctx->sig_rl->gid = issuer_ctx->ipriv_key->gid;
        issuer_ctx->sig_rl->version = octstr32_0;
        issuer_ctx->sig_rl->n2 = octstr32_0;

        *ctx = issuer_ctx;
        result = kEpidNoErr;
    } while (0);

    if (kEpidNoErr != result) {
        EpidIssuerDelete(&issuer_ctx);
    }

    return (kEpidNoErr);
}

void EpidIssuerDelete(IssuerCtx **ctx) {
    if (ctx && *ctx) {
        DeleteGroupPubKey(&(*ctx)->pub_key);
        DeleteEpid2Params(&(*ctx)->epid2_params);
        DeleteIssueKey(&(*ctx)->ipriv_key);
        SAFE_FREE((*ctx)->priv_rl);
        SAFE_FREE((*ctx)->sig_rl);
        SAFE_FREE(*ctx);
        *ctx = NULL;
    }
}