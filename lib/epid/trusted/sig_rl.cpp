
#include <epid/sig_rl.h>
#include <util/memory.h>

std::string SignatureRl::hash(const std::shared_ptr<uint8_t> &value, size_t size) {
    sgx_sha256_hash_t hash{};
    if (sgx_sha256_msg(value.get(), size, &hash) != SGX_SUCCESS) {
        return "";
    }
    return {(char *)hash, sizeof(sgx_sha256_hash_t)};
}

bool SignatureRl::push(const std::shared_ptr<uint8_t> &value, size_t size) {
    auto h = hash(value, size);
    if (h.empty()) {
        return false;
    }
    this->data[h].push_back({size, value});
    return true;
}

bool SignatureRl::exists(const std::shared_ptr<uint8_t> &value, size_t size) {
    auto h = hash(value, size);
    if (h.empty()) {
        return false;
    }

    auto it = this->data.find(h);
    if (it == this->data.end()) {
        return false;
    }

    for (const auto &item : it->second) {
        if (item.size == size && memcmp(item.value.get(), value.get(), size) == 0) {
            return true;
        }
    }

    return false;
}

size_t SignatureRl::serializedSize() {
    size_t size = sizeof(size_t);
    for (const auto &item : this->data) {
        for (const auto &sig : item.second) {
            size += sizeof(size_t);
            size += sig.size;
        }
    }
    return size;
}

std::shared_ptr<uint8_t> SignatureRl::serialize() {
    auto buffer = Memory::makeShared<uint8_t>(this->serializedSize());
    if (buffer == nullptr) {
        return buffer;
    }
    size_t total = 0;
    auto p = buffer.get() + sizeof(size_t);
    for (const auto &item : this->data) {
        for (const auto &sig : item.second) {
            total++;
            memcpy(p, &sig.size, sizeof(size_t));
            p += sizeof(size_t);
            memcpy(p, sig.value.get(), sig.size);
            p += sig.size;
        }
    }
    memcpy(buffer.get(), &total, sizeof(size_t));
    return buffer;
}

bool SignatureRl::deserialize(const std::shared_ptr<uint8_t> &buffer) {
    if (buffer == nullptr) {
        return false;
    }
    this->data = std::unordered_map<std::string, std::vector<SignatureRlItem>>();
    size_t total = 0;
    auto p = buffer.get();
    memcpy(&total, p, sizeof(size_t));
    if (total < 0) {
        return false;
    }
    p += sizeof(size_t);
    for (size_t i = 0; i < total; i++) {
        size_t size = 0;
        memcpy(&size, p, sizeof(size_t));
        p += sizeof(size_t);
        if (size < 0) {
            return false;
        }
        auto value = Memory::makeShared<uint8_t>(size);
        if (value == nullptr) {
            return false;
        }
        memcpy(value.get(), p, size);
        p += size;
        this->push(value, size);
    }
    return true;
}
