#include <kj/debug.h>
#include <kj/encoding.h>
#include <kj/memory.h>

#include "serialize.h"
#include "rpc-noise.h"

namespace capnp {

class NoiseVatNetwork::Connection::OutgoingMessageImpl final : public OutgoingRpcMessage, public kj::Refcounted {
  public:
    OutgoingMessageImpl(Connection& conn, uint firstSegmentWordSize) :
      conn(conn),
      message(firstSegmentWordSize == 0 ? SUGGESTED_FIRST_SEGMENT_WORDS : firstSegmentWordSize) {}

    AnyPointer::Builder getBody() override {
      return message.getRoot<AnyPointer>();
    }

    void send() override {
      auto& previousWrite = KJ_ASSERT_NONNULL(this->conn.previousWrite, "connection already shut down");
      this->conn.previousWrite = previousWrite
        .then([this]() {
          return this->conn.msgStream->writeMessage(this->message);
        }).attach(kj::addRef(*this));
    }

    size_t sizeInWords() override {
      return this->message.sizeInWords();
    }

  private:
    Connection& conn;
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
  KJ_IF_SOME(stream, this->streamM) {
    auto f = kj::heap<NoiseVatNetwork::Connection>(kj::mv(stream));
    this->foo = f;
    return f;
  } else {
    kj::throwFatalException(KJ_EXCEPTION(UNIMPLEMENTED, "foo"));
  }
}

kj::Promise<kj::Own<NoiseVatNetworkBase::Connection>> NoiseVatNetwork::accept() {
  KJ_IF_SOME(receiver, this->receiverM) {
    return receiver->accept().then([this](kj::Own<kj::AsyncIoStream> stream) {
      auto f = kj::heap<NoiseVatNetwork::Connection>(mv(stream));
      this->foo = f;
      return kj::Own<NoiseVatNetworkBase::Connection>(kj::mv(f));
    });
  } else {
    KJ_IF_SOME(bindAddress, this->bindAddressM) {
      this->receiverM = bindAddress->listen();
      return accept();
    } else {
      // Create a promise that will never be fulfilled.
      auto paf = kj::newPromiseAndFulfiller<kj::Own<NoiseVatNetworkBase::Connection>>();
      this->acceptFulfiller = kj::mv(paf.fulfiller);
      return kj::mv(paf.promise);
    }
  }
}

kj::Promise<void> NoiseVatNetwork::doFoo() {
  return KJ_ASSERT_NONNULL(this->foo, "foo").shutdown();
}

NoiseVatNetwork::Connection::Connection(kj::Own<kj::AsyncIoStream> stream) : bar(*stream), previousWrite(kj::READY_NOW), peerVatId(4) {
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
  KJ_LOG(ERROR, "w");
  return this->msgStream->tryReadMessage()
    .then([](auto msgReaderM) {
      KJ_LOG(ERROR, "q");
      return msgReaderM.map([](kj::Own<capnp::MessageReader>& msgReader) -> kj::Own<IncomingRpcMessage> {
        return kj::heap<IncomingMessageImpl>(kj::mv(msgReader));
      });
    });
}

kj::Promise<void> NoiseVatNetwork::Connection::shutdown() {
  KJ_LOG(ERROR, "FOO");
  kj::Promise<void> result = KJ_ASSERT_NONNULL(this->previousWrite, "already shut down").then([this]() {
    return this->msgStream->end();
  });

  this->previousWrite = kj::none;
  return kj::mv(result);
}

rpc::noise::VatId::Reader NoiseVatNetwork::Connection::getPeerVatId() {
  KJ_LOG(ERROR, "getPeerVatId()");
  return this->peerVatId.getRoot<rpc::noise::VatId>();
}

} // namespace capnp
