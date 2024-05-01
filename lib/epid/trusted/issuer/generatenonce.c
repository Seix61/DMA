
#include <epid/issuer/context.h>
#include <epid/issuer/api.h>
#include <ippmath/memory.h>

EpidStatus EpidIssuerGenerateNonce(IssuerCtx *ctx, IssuerNonce *ni) {
    EpidStatus result = kEpidNoErr;
    if (0 != ctx->rnd_func((unsigned int *) &ctx->ni, sizeof(IssuerNonce) * 8, NULL)) {
        result = kEpidErr;
    }
    memcpy_S(ni, sizeof(IssuerNonce), &ctx->ni, sizeof(IssuerNonce));
    return result;
}
