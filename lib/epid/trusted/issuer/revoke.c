
#include <epid/issuer/context.h>
#include <epid/issuer/api.h>
#include <ippmath/memory.h>
#include <common/endian_convert.h>
#include <common/sigrlvalid.h>
#include <epid/util/rl_size.h>
#include <epid/util/rl_valid.h>

#define OCTSTR32_LOAD(oct, u32)      \
    do {                              \
      oct.data[0] = (unsigned char)((((uint32_t)(u32)) & 0xFF000000) >> 24);   \
      oct.data[1] = (unsigned char)((((uint32_t)(u32)) & 0xFF0000) >> 16);   \
      oct.data[2] = (unsigned char)((((uint32_t)(u32)) & 0xFF00) >> 8);   \
      oct.data[3] = (unsigned char)((((uint32_t)(u32)) & 0xFF));   \
    } while(0);

EpidStatus EpidRevokePriv(IssuerCtx *ctx, const FpElemStr *priv) {
    EpidStatus result = kEpidNoErr;

    do {
        if (!priv || !ctx) {
            result = kEpidBadArgErr;
            break;
        }
        PrivRl *new_ptr = SAFE_REALLOC(ctx->priv_rl, EpidGetPrivRlSize(ctx->priv_rl) + sizeof(FpElemStr));
        if (!new_ptr) {
            result = kEpidMemAllocErr;
            break;
        }

        ctx->priv_rl = new_ptr;
        uint32_t n1 = ntohl(new_ptr->n1);
        if (memcpy_S(&new_ptr->f[n1], sizeof(FpElemStr), priv, sizeof(FpElemStr)) != 0) {
            result = kEpidErr;
            break;
        }

        OCTSTR32_LOAD(new_ptr->n1, n1 + 1)
        new_ptr->version = new_ptr->n1;

        if (!IsPrivRlValid(&ctx->ipriv_key->gid, new_ptr, EpidGetPrivRlSize(new_ptr))) {
            result = kEpidNotImpl;
        }
    } while (0);

    return result;
}

EpidStatus EpidRevokeSig(IssuerCtx *ctx, const EpidSignature *raw_sig) {
    EpidStatus result = kEpidNoErr;
    EpidSplitSignature *sig = (EpidSplitSignature *) raw_sig;

    do {
        if (!sig || !ctx) {
            result = kEpidBadArgErr;
            break;
        }
        SigRl *new_ptr = SAFE_REALLOC(ctx->sig_rl, EpidGetSigRlSize(ctx->sig_rl) + sizeof(SigRlEntry));
        if (!new_ptr) {
            result = kEpidMemAllocErr;
            break;
        }

        ctx->sig_rl = new_ptr;
        uint32_t n2 = ntohl(new_ptr->n2);
        if (memcpy_S(&new_ptr->bk[n2].b, sizeof(G1ElemStr), &sig->sigma0.B, sizeof(G1ElemStr)) != 0
            || memcpy_S(&new_ptr->bk[n2].k, sizeof(G1ElemStr), &sig->sigma0.K, sizeof(G1ElemStr)) != 0) {
            result = kEpidErr;
            break;
        }

        OCTSTR32_LOAD(new_ptr->n2, n2 + 1)
        new_ptr->version = new_ptr->n2;

        if (!IsSigRlValid(&ctx->ipriv_key->gid, new_ptr, EpidGetSigRlSize(new_ptr))) {
            result = kEpidNotImpl;
        }
    } while (0);

    return result;
}
