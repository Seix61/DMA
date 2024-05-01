
#ifndef LIB_TRUSTED_EPID_SIG_RL_H
#define LIB_TRUSTED_EPID_SIG_RL_H

#include <unordered_map>
#include <vector>
#include <string>
#include <sgx_tcrypto.h>

struct SignatureRlItem {
    size_t size;
    std::shared_ptr<uint8_t> value;
};

class SignatureRl {
private:
    std::unordered_map<std::string, std::vector<SignatureRlItem>> data;

    std::string hash(const std::shared_ptr<uint8_t> &value, size_t size);

public:
    bool push(const std::shared_ptr<uint8_t> &value, size_t size);

    bool exists(const std::shared_ptr<uint8_t> &value, size_t size);

    size_t serializedSize();

    std::shared_ptr<uint8_t> serialize();

    bool deserialize(const std::shared_ptr<uint8_t> &buffer);
};

#endif //LIB_TRUSTED_EPID_SIG_RL_H
