
#ifndef LIB_TRUSTED_UTIL_SGX_RANDOM_H
#define LIB_TRUSTED_UTIL_SGX_RANDOM_H

class Random {
public:
    static int nextInt();

    static int nextInt(int min, int max);
};

#endif //LIB_TRUSTED_UTIL_SGX_RANDOM_H
