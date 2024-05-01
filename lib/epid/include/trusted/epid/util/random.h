
#ifndef LIB_TRUSTED_EPID_UTIL_RANDOM_H
#define LIB_TRUSTED_EPID_UTIL_RANDOM_H

#define ROUND_TO(x, align) (((x) + ((align)-1)) & ~((align)-1))

int epid_random_func(unsigned int *p_random_data, int bits, void *p_user_data);

#endif //LIB_TRUSTED_EPID_UTIL_RANDOM_H
