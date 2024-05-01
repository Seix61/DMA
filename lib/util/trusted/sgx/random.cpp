
#include <util/sgx/random.h>
#include <sgx_trts.h>
#include <cstdlib>

int Random::nextInt() {
    int result;
    sgx_read_rand(reinterpret_cast<unsigned char *>(&result), sizeof(result));
    return result;
}

int Random::nextInt(int min, int max) {
    return min + std::abs(nextInt()) % (max - min + 1);
}
