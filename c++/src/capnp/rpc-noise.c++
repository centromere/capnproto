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

    ~IncomingMessageImpl() noexcept(false) {}

  private:
    kj::Own<capnp::MessageReader> msgReader;
};

NoiseVatNetwork::NoiseVatNetwork(kj::Maybe<kj::Own<kj::NetworkAddress>> bindAddressM) : bindAddressM(kj::mv(bindAddressM)) {}

NoiseVatNetwork::NoiseVatNetwork(kj::Own<kj::AsyncIoStream> stream) : streamM(kj::mv(stream)) {}

NoiseVatNetwork::~NoiseVatNetwork() noexcept(false) {};

kj::Maybe<kj::Own<NoiseVatNetworkBase::Connection>> NoiseVatNetwork::connect(rpc::noise::VatId::Reader hostId) {
  KJ_IF_MAYBE(stream, this->streamM) {
    return kj::heap<NoiseVatNetwork::Connection>(kj::mv(*stream));
  } else {
    kj::throwFatalException(KJ_EXCEPTION(UNIMPLEMENTED, "foo"));
  }
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
      // Create a promise that will never be fulfilled.
      auto paf = kj::newPromiseAndFulfiller<kj::Own<NoiseVatNetworkBase::Connection>>();
      this->acceptFulfiller = kj::mv(paf.fulfiller);
      return kj::mv(paf.promise);
    }
  }
}

class OutgoingMessageImpl final : public OutgoingRpcMessage, public kj::Refcounted {
  public:
    OutgoingMessageImpl(uint firstSegmentWordSize, NoiseVatNetwork::Connection& conn) :
      message(firstSegmentWordSize == 0 ? SUGGESTED_FIRST_SEGMENT_WORDS : firstSegmentWordSize), conn(conn) {}

    ~OutgoingMessageImpl() noexcept(false) { std::cout << "OutgoingMessageImpl dtor" << std::endl; }

    AnyPointer::Builder getBody() {
      return message.getRoot<AnyPointer>();
    }

    void send() {
      conn.previousWrite = conn.previousWrite.then([this]() {
        return conn.msgStream->writeMessage(this->message).attach(kj::addRef(*this));
      }).attach(kj::addRef(*this));
    }

    size_t sizeInWords() {
      KJ_LOG(ERROR, "sizeInWords");
      kj::throwFatalException(KJ_EXCEPTION(UNIMPLEMENTED, "sizeInWords"));
    }

   private:
     MallocMessageBuilder message;
     NoiseVatNetwork::Connection& conn;
};

kj::Own<OutgoingRpcMessage> NoiseVatNetwork::Connection::newOutgoingMessage(uint firstSegmentWordSize) {
  return kj::refcounted<OutgoingMessageImpl>(firstSegmentWordSize, *this);
}

kj::Promise<kj::Maybe<kj::Own<IncomingRpcMessage>>> NoiseVatNetwork::Connection::receiveIncomingMessage() {
  return this->msgStream->tryReadMessage()
    .then([](auto msgReaderM) {
      KJ_IF_MAYBE(foo, msgReaderM) {
        std::cout << "good" << std::endl;
      } else {
        std::cout << "not good" << std::endl;
      }
      return msgReaderM.map([](kj::Own<capnp::MessageReader>& msgReader) {
        return kj::Own<IncomingRpcMessage>(kj::heap<IncomingMessageImpl>(kj::mv(msgReader)));
      });
    });
}

kj::Promise<void> NoiseVatNetwork::Connection::shutdown() {
  this->msgStream->end();
  return kj::READY_NOW;
}

NoiseVatNetwork::Connection::Connection(kj::Own<kj::AsyncIoStream> stream) : previousWrite(kj::READY_NOW) {
  this->msgStream = kj::heap<capnp::AsyncIoMessageStream>(*stream).attach(kj::mv(stream));
}

rpc::noise::VatId::Reader NoiseVatNetwork::Connection::getPeerVatId() {
  word scratch[4];
  std::memset(scratch, 0, sizeof(scratch));
  MallocMessageBuilder b(scratch);
  auto f = b.getRoot<rpc::noise::VatId>();
  return f;
}

} // namespace capnp
