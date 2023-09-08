#include <iostream>

#include <kj/debug.h>
#include <kj/memory.h>

#include "serialize-async.h"
#include <kj/encoding.h>

#include "rpc-noise.h"

namespace capnp {

class NoiseVatNetwork::Connection::OutgoingMessageImpl final : public OutgoingRpcMessage, public kj::Refcounted {
  public:
    OutgoingMessageImpl(Connection& connection, uint firstSegmentWordSize) :
      connection(connection),
      message(firstSegmentWordSize == 0 ? SUGGESTED_FIRST_SEGMENT_WORDS : firstSegmentWordSize) {}

    AnyPointer::Builder getBody() {
      return message.getRoot<AnyPointer>();
    }

    void send() {
      auto& previousWrite = KJ_ASSERT_NONNULL(this->connection.previousWrite, "connection already shut down");
      this->connection.previousWrite = previousWrite
        .then([this]() {
          return this->connection.msgStream->writeMessage(this->message)
            .attach(kj::addRef(*this));
        }).attach(kj::addRef(*this));
    }

    size_t sizeInWords() {
      KJ_LOG(ERROR, "sizeInWords");
      kj::throwFatalException(KJ_EXCEPTION(UNIMPLEMENTED, "sizeInWords"));
    }

  private:
    Connection& connection;
    MallocMessageBuilder message;
};

class NoiseVatNetwork::Connection::IncomingMessageImpl final: public IncomingRpcMessage {
  public:
    IncomingMessageImpl(kj::Own<capnp::MessageReader> msgReader) : msgReader(kj::mv(msgReader)) {}

    AnyPointer::Reader getBody() override {
      return this->msgReader->getRoot<AnyPointer>();
    }

    size_t sizeInWords() override {
      return this->msgReader->sizeInWords();
    }

  private:
    kj::Own<capnp::MessageReader> msgReader;
};

NoiseVatNetwork::NoiseVatNetwork(kj::Maybe<kj::Own<kj::NetworkAddress>> bindAddressM) : bindAddressM(kj::mv(bindAddressM)) {}

NoiseVatNetwork::NoiseVatNetwork(kj::Own<kj::AsyncIoStream> stream) : streamM(kj::mv(stream)) {}

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

NoiseVatNetwork::Connection::Connection(kj::Own<kj::NoiseConnection> stream) : previousWrite(kj::READY_NOW), peerVatId(4) {
  this->msgStream = kj::heap<capnp::AsyncIoMessageStream>(*stream).attach(kj::mv(stream));

  auto keyBytes = this->peerVatId.initRoot<rpc::noise::VatId>()
    .initPublicKey()
    .initX25519()
    .initBytes();

  keyBytes.setA(65535);
  keyBytes.setB(255);
  keyBytes.setC(65535);
  keyBytes.setD(254);
}

kj::Own<OutgoingRpcMessage> NoiseVatNetwork::Connection::newOutgoingMessage(uint firstSegmentWordSize) {
  return kj::refcounted<OutgoingMessageImpl>(*this, firstSegmentWordSize);
}

kj::Promise<kj::Maybe<kj::Own<IncomingRpcMessage>>> NoiseVatNetwork::Connection::receiveIncomingMessage() {
  return this->msgStream->tryReadMessage()
    .then([](auto msgReaderM) {
      return msgReaderM.map([](kj::Own<capnp::MessageReader>& msgReader) -> kj::Own<IncomingRpcMessage> {
        return kj::heap<IncomingMessageImpl>(kj::mv(msgReader));
      });
    });
}

kj::Promise<void> NoiseVatNetwork::Connection::shutdown() {
  this->msgStream->end();
  this->previousWrite = nullptr;

  return kj::READY_NOW;
}

rpc::noise::VatId::Reader NoiseVatNetwork::Connection::getPeerVatId() {
  KJ_LOG(ERROR, "getPeerVatId()");
  return this->peerVatId.getRoot<rpc::noise::VatId>();
}

} // namespace capnp
