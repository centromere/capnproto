#include <iostream>

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
          auto x = this->message.getSegmentsForOutput();
          auto y = kj::heapArray<byte>(this->message.sizeInWords());
          auto ptr = y.begin();
          int i = 0;
          while (ptr != y.end()) {
            std::memcpy(ptr, x[i].begin(), x[i].size());
            ptr += x[i].size();
            i++;
          }

          return this->conn.inner->writeMessage(y)
            .attach(kj::addRef(*this)).attach(kj::mv(y));
        }).attach(kj::addRef(*this));
    }

    size_t sizeInWords() override {
      KJ_LOG(ERROR, "sizeInWords");
      kj::throwFatalException(KJ_EXCEPTION(UNIMPLEMENTED, "sizeInWords"));
    }

  private:
    Connection& conn;
    MallocMessageBuilder message;
};

class NoiseVatNetwork::Connection::IncomingMessageImpl final: public IncomingRpcMessage {
  public:
    IncomingMessageImpl(const kj::ArrayPtr<const word> msg) {
      this->msgReader = kj::heap<FlatArrayMessageReader>(msg);
    }

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

NoiseVatNetwork::NoiseVatNetwork(kj::Own<kj::AsyncIoMessageStream> stream) : streamM(kj::mv(stream)) {}

kj::Maybe<kj::Own<NoiseVatNetworkBase::Connection>> NoiseVatNetwork::connect(rpc::noise::VatId::Reader hostId) {
  KJ_IF_MAYBE(stream, this->streamM) {
    return kj::heap<NoiseVatNetwork::Connection>(kj::mv(*stream));
  } else {
    kj::throwFatalException(KJ_EXCEPTION(UNIMPLEMENTED, "foo"));
  }
}

kj::Promise<kj::Own<NoiseVatNetworkBase::Connection>> NoiseVatNetwork::accept() {
  KJ_IF_MAYBE(receiver, this->receiverM) {
    return (*receiver)->acceptMsg().then([](kj::Own<kj::AsyncIoMessageStream> stream) {
      return kj::Own<NoiseVatNetworkBase::Connection>(kj::heap<NoiseVatNetwork::Connection>(mv(stream)));
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

NoiseVatNetwork::Connection::Connection(kj::Own<kj::AsyncIoMessageStream> stream) : inner(kj::mv(stream)), previousWrite(kj::READY_NOW), peerVatId(4) {
  /*this->msgStream = kj::heap<capnp::AsyncIoMessageStream>(*stream).attach(kj::mv(stream));

  auto keyBytes = this->peerVatId.initRoot<rpc::noise::VatId>()
    .initPublicKey()
    .initX25519()
    .initBytes();

  keyBytes.setA(65535);
  keyBytes.setB(255);
  keyBytes.setC(65535);
  keyBytes.setD(254);*/
}

kj::Own<OutgoingRpcMessage> NoiseVatNetwork::Connection::newOutgoingMessage(uint firstSegmentWordSize) {
  return kj::refcounted<OutgoingMessageImpl>(*this, firstSegmentWordSize);
}

kj::Promise<kj::Maybe<kj::Own<IncomingRpcMessage>>> NoiseVatNetwork::Connection::receiveIncomingMessage() {
  return this->inner->tryReadMessage()
    .then([](auto msgM) -> kj::Maybe<kj::Own<IncomingRpcMessage>> {
      auto& msg = KJ_ASSERT_NONNULL(msgM, "failed to receive message");
      KJ_LOG(ERROR, "Bar", msg.size());
      auto x = kj::arrayPtr<const word>((const word *)msg.begin(), msg.size());
      size_t expected = expectedSizeInWordsFromPrefix(x);
      KJ_LOG(ERROR, "Foo", expected, x.size());
      return kj::heap<IncomingMessageImpl>(x);
    });
}

kj::Promise<void> NoiseVatNetwork::Connection::shutdown() {
  this->previousWrite = nullptr;

  return kj::READY_NOW;
}

rpc::noise::VatId::Reader NoiseVatNetwork::Connection::getPeerVatId() {
  KJ_LOG(ERROR, "getPeerVatId()");
  return this->peerVatId.getRoot<rpc::noise::VatId>();
}

} // namespace capnp
