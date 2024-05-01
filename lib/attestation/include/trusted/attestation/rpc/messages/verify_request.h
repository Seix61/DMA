
#ifndef LIB_TRUSTED_ATTESTATION_RPC_MESSAGE_VERIFY_REQUEST_H
#define LIB_TRUSTED_ATTESTATION_RPC_MESSAGE_VERIFY_REQUEST_H

#include <attestation/dma_quote.h>
#include <attestation/rpc/message_base.h>
#include <util/memory.h>
#include <sgx_report.h>

namespace Attestation {
    class VerifyRequestMessage : public MessageBase {
    private:
        size_t size;
        std::shared_ptr<dma_quote> quote;
    public:
        VerifyRequestMessage() : MessageBase(VerifyRequest), size(0), quote() {}

        explicit VerifyRequestMessage(size_t size, const std::shared_ptr<dma_quote> &quote) :
                MessageBase(VerifyRequest), size(size), quote(quote) {}

        size_t getSize() const {
            return size;
        }

        const std::shared_ptr<dma_quote> &getQuote() const {
            return quote;
        }

        void serialize(std::ostringstream &oss) const override {
            oss.write((char *) &size, sizeof(size));
            oss.write((char *) quote.get(), size);
        }

        void deserialize(std::istringstream &iss) override {
            iss.read((char *) &size, sizeof(size));
            quote = Memory::makeShared<dma_quote>(size);
            iss.read((char *) quote.get(), size);
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

#endif //LIB_TRUSTED_ATTESTATION_RPC_MESSAGE_VERIFY_REQUEST_H
