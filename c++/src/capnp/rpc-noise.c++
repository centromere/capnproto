#include <iostream>

#include <kj/debug.h>
#include <kj/memory.h>

#include "serialize-async.h"

#include "rpc-noise.h"

namespace capnp {

class NoiseVatNetwork::IncomingMessageImpl final: public IncomingRpcMessage {
  public:
    IncomingMessageImpl(kj::Own<capnp::MessageReader> msgReader) : msgReader(kj::mv(msgReader)) {}

    AnyPointer::Reader getBody() override {
      return this->msgReader->getRoot<AnyPointer>();
    }

    size_t sizeInWords() override {
      return this->msgReader->sizeInWords();
    }

    ~IncomingMessageImpl() {}

  private:
    kj::Own<capnp::MessageReader> msgReader;
};

NoiseVatNetwork::NoiseVatNetwork(kj::Maybe<kj::Own<kj::NetworkAddress>> bindAddressM) : bindAddressM(kj::mv(bindAddressM)) {}

NoiseVatNetwork::~NoiseVatNetwork() noexcept(false) {};

kj::Maybe<kj::Own<NoiseVatNetworkBase::Connection>> NoiseVatNetwork::connect(rpc::noise::VatId::Reader hostId) {
  return nullptr;
}

kj::Promise<kj::Own<NoiseVatNetworkBase::Connection>> NoiseVatNetwork::accept() {
  KJ_IF_MAYBE(receiver, this->receiverM) {
    return (*receiver)->accept().then([](kj::Own<kj::AsyncIoStream> stream) {
      return kj::Own<NoiseVatNetworkBase::Connection>(kj::heap<NoiseVatNetwork::Connection>(kj::mv(stream)));
    });
  } else {
    KJ_IF_MAYBE(bindAddress, this->bindAddressM) {
      this->receiverM = (*bindAddress)->listen();
      return accept();
    } else {
      return KJ_EXCEPTION(FAILED, "attempt to accept() without a bind address");
    }
  }
}

kj::Own<OutgoingRpcMessage> NoiseVatNetwork::Connection::newOutgoingMessage(uint firstSegmentWordSize) {
  return kj::Own<OutgoingRpcMessage>();
}

kj::Promise<kj::Maybe<kj::Own<IncomingRpcMessage>>> NoiseVatNetwork::Connection::receiveIncomingMessage() {
  return this->msgStream->tryReadMessage()
    .then([](auto msgReaderM) {
      return msgReaderM.map([](kj::Own<capnp::MessageReader>& msgReader) {
        return kj::Own<IncomingRpcMessage>(kj::heap<IncomingMessageImpl>(kj::mv(msgReader)));
      });
    });
}

kj::Promise<void> NoiseVatNetwork::Connection::shutdown() {
  return kj::READY_NOW;
}

NoiseVatNetwork::Connection::Connection(kj::Own<kj::AsyncIoStream> stream) {
  this->msgStream = kj::heap<capnp::AsyncIoMessageStream>(*stream).attach(kj::mv(stream));
}

rpc::noise::VatId::Reader NoiseVatNetwork::Connection::getPeerVatId() {
}

} // namespace capnp
