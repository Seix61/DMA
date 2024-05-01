
#ifndef LIB_TRUSTED_EPID_UTIL_RL_VALID_H
#define LIB_TRUSTED_EPID_UTIL_RL_VALID_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <epid/types.h>
#include <epid/stdtypes.h>

bool IsPrivRlValid(GroupId const *gid, PrivRl const *priv_rl, size_t priv_rl_size);

#ifdef __cplusplus
}
#endif

#endif //LIB_TRUSTED_EPID_UTIL_RL_VALID_H
