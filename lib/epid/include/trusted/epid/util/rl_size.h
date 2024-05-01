
#ifndef LIB_TRUSTED_EPID_UTIL_RL_SIZE_H
#define LIB_TRUSTED_EPID_UTIL_RL_SIZE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <epid/types.h>

uint32_t EpidGetPrivRlSize(PrivRl *priv_rl);

uint32_t EpidGetSigRlSize(SigRl *sig_rl);

#ifdef __cplusplus
}
#endif

#endif //LIB_TRUSTED_EPID_UTIL_RL_SIZE_H
