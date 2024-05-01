
#ifndef LIB_TRUSTED_EPID_RPC_MESSAGE_SIG_RL_RESPONSE_H
#define LIB_TRUSTED_EPID_RPC_MESSAGE_SIG_RL_RESPONSE_H

#include <cstdint>
#include <epid/rpc/message_base.h>
#include <util/memory.h>
#include <epid/types.h>

namespace Epid {
    class SigRLResponseMessage : public MessageBase {
    private:
        size_t size;
        std::shared_ptr<SigRl> rl;
    public:
        SigRLResponseMessage() : MessageBase(SigRLResponse), size(0), rl() {}

        explicit SigRLResponseMessage(size_t size, const std::shared_ptr<SigRl> &rl) :
                MessageBase(SigRLResponse), size(size), rl(rl) {}

        size_t getSize() const {
            return size;
        }

        const std::shared_ptr<SigRl> &getRl() const {
            return rl;
        }

        void serialize(std::ostringstream &oss) const override {
            oss.write((char *) &size, sizeof(size));
            oss.write((char *) rl.get(), size);
        }

        void deserialize(std::istringstream &iss) override {
            iss.read((char *) &size, sizeof(size));
            rl = Memory::makeShared<SigRl>(size);
            iss.read((char *) rl.get(), size);
        }

        static size_t staticSize() {
            return 0;
        }

        static size_t contentSize() {
            return 0;
        }

        static size_t serializedSize() {
            return MessageBase::serializedSize() + contentSize();
        }
    };
}

#endif //LIB_TRUSTED_EPID_RPC_MESSAGE_SIG_RL_RESPONSE_H
