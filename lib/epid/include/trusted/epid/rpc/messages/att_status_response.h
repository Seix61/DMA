
#ifndef LIB_TRUSTED_EPID_RPC_MESSAGE_ATT_STATUS_RESPONSE_H
#define LIB_TRUSTED_EPID_RPC_MESSAGE_ATT_STATUS_RESPONSE_H

#include <cstdint>
#include <epid/rpc/message_base.h>
#include <util/memory.h>

namespace Epid {
    class AttStatusResponseMessage : public MessageBase {
    private:
        uint32_t status;
    public:
        AttStatusResponseMessage() : MessageBase(AttStatusResponse), status(-1) {}

        explicit AttStatusResponseMessage(uint32_t status) : MessageBase(AttStatusResponse), status(status) {}

        uint32_t getStatus() const {
            return status;
        }

        void serialize(std::ostringstream &oss) const override {
            oss.write((char *) &status, sizeof(status));
        }

        void deserialize(std::istringstream &iss) override {
            iss.read((char *) &status, sizeof(status));
        }

        static size_t contentSize() {
            return sizeof(status);
        }

        static size_t serializedSize() {
            return MessageBase::serializedSize() + contentSize();
        }
    };
}

#endif //LIB_TRUSTED_EPID_RPC_MESSAGE_ATT_STATUS_RESPONSE_H
