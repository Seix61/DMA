
#include <epid/issuer/api.h>
#include <common/endian_convert.h>

uint32_t EpidGetPrivRlSize(PrivRl *priv_rl) {
    const uint32_t kMinSize = sizeof(PrivRl) - sizeof(FpElemStr);
    if (!priv_rl) {
        return kMinSize;
    } else {
        if (ntohl(priv_rl->n1) > (SIZE_MAX - kMinSize) / sizeof(FpElemStr)) {
            return kMinSize;
        } else {
            return (uint32_t) (kMinSize + ntohl(priv_rl->n1) * sizeof(FpElemStr));
        }
    }
}

uint32_t EpidGetSigRlSize(SigRl *sig_rl) {
    const uint32_t kMinSize = sizeof(SigRl) - sizeof(SigRlEntry);
    if (!sig_rl) {
        return kMinSize;
    } else {
        if (ntohl(sig_rl->n2) > (SIZE_MAX - kMinSize) / sizeof(SigRlEntry)) {
            return kMinSize;
        } else {
            return (uint32_t) (kMinSize + ntohl(sig_rl->n2) * sizeof(SigRlEntry));
        }
    }
}
