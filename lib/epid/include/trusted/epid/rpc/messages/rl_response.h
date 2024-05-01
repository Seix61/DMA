
#ifndef LIB_TRUSTED_EPID_RPC_MESSAGE_RL_RESPONSE_H
#define LIB_TRUSTED_EPID_RPC_MESSAGE_RL_RESPONSE_H

#include <cstdint>
#include <epid/rpc/message_base.h>
#include <util/memory.h>
#include <epid/types.h>

namespace Epid {
    class RLResponseMessage : public MessageBase {
    private:
        size_t sigRlSize;
        std::shared_ptr<SigRl> sigRl;
        size_t privRlSize;
        std::shared_ptr<PrivRl> privRl;
        size_t signatureRlSize;
        std::shared_ptr<uint8_t> signatureRl;
    public:
        RLResponseMessage() : MessageBase(RLResponse),
                sigRlSize(0), sigRl(),
                privRlSize(0), privRl(),
                signatureRlSize(0), signatureRl() {}

        explicit RLResponseMessage(size_t sigRlSize, const std::shared_ptr<SigRl> &sigRl, size_t privRlSize, const std::shared_ptr<PrivRl> &privRl, size_t signatureRlSize, const std::shared_ptr<uint8_t> &signatureRl) :
                MessageBase(RLResponse),
                sigRlSize(sigRlSize), sigRl(sigRl),
                privRlSize(privRlSize), privRl(privRl),
                signatureRlSize(signatureRlSize), signatureRl(signatureRl) {}

        size_t getSigRlSize() const {
            return sigRlSize;
        }

        const std::shared_ptr<SigRl> &getSigRl() const {
            return sigRl;
        }

        size_t getPrivRlSize() const {
            return privRlSize;
        }

        const std::shared_ptr<PrivRl> &getPrivRl() const {
            return privRl;
        }

        size_t getSignatureRlSize() const {
            return signatureRlSize;
        }

        const std::shared_ptr<uint8_t> &getSignatureRl() const {
            return signatureRl;
        }

        void serialize(std::ostringstream &oss) const override {
            oss.write((char *) &sigRlSize, sizeof(sigRlSize));
            oss.write((char *) sigRl.get(), sigRlSize);
            oss.write((char *) &privRlSize, sizeof(privRlSize));
            oss.write((char *) privRl.get(), privRlSize);
            oss.write((char *) &signatureRlSize, sizeof(signatureRlSize));
            oss.write((char *) signatureRl.get(), signatureRlSize);
        }

        void deserialize(std::istringstream &iss) override {
            iss.read((char *) &sigRlSize, sizeof(sigRlSize));
            sigRl = Memory::makeShared<SigRl>(sigRlSize);
            iss.read((char *) sigRl.get(), sigRlSize);
            iss.read((char *) &privRlSize, sizeof(privRlSize));
            privRl = Memory::makeShared<PrivRl>(privRlSize);
            iss.read((char *) privRl.get(), privRlSize);
            iss.read((char *) &signatureRlSize, sizeof(signatureRlSize));
            signatureRl = Memory::makeShared<uint8_t>(signatureRlSize);
            iss.read((char *) signatureRl.get(), signatureRlSize);
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

#endif //LIB_TRUSTED_EPID_RPC_MESSAGE_RL_RESPONSE_H
