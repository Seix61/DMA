
#include <epid/util/rl_valid.h>
#include <string.h>
#include <common/endian_convert.h>

bool IsPrivRlValid(GroupId const *gid, PrivRl const *priv_rl, size_t priv_rl_size) {
    const size_t kMinPrivRlSize = sizeof(PrivRl) - sizeof(FpElemStr);
    size_t input_priv_rl_size = 0;

    if (!gid || !priv_rl || kMinPrivRlSize > priv_rl_size) {
        return false;
    }
    if (ntohl(priv_rl->n1) >
        (SIZE_MAX - kMinPrivRlSize) / sizeof(priv_rl->f[0])) {
        return false;
    }
    // sanity check of input PrivRl size
    input_priv_rl_size =
            kMinPrivRlSize + ntohl(priv_rl->n1) * sizeof(priv_rl->f[0]);
    if (input_priv_rl_size != priv_rl_size) {
        return false;
    }
    // verify that gid given and gid in PrivRl match
    if (0 != memcmp(gid, &priv_rl->gid, sizeof(*gid))) {
        return false;
    }
    return true;
}