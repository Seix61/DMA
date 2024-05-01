
#include <epid/util/random.h>
#include <sgx_trts.h>
#include <cassert>

int epid_random_func(unsigned int *p_random_data, int bits, void *p_user_data) {
    (void) (p_user_data);
    assert(!(bits % 8));

    if (SGX_SUCCESS != sgx_read_rand((uint8_t *) p_random_data, ROUND_TO(bits, 8) / 8)) {
        return 1;
    }
    return 0;
}