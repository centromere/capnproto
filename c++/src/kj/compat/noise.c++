#include <iostream>
#include <variant>

#include <kj/debug.h>
#include <kj/encoding.h>
#include <kj/string-tree.h>

#include "noise.h"

namespace kj {

namespace {

class NoisePeerIdentityImpl final: public NoisePeerIdentity {
  public:
    NoisePeerIdentityImpl(const kj::StringPtr identityStr) : key(identityStr) {
    }

    kj::String toString() override {
      return kj::str(this->key.getPublicData().asBase64());
    }

  private:
    const PublicKey<Curve25519> key;
};

}  // namespace

class NoiseNetworkAddress final: public kj::NetworkAddress {
  public:
    NoiseNetworkAddress(NoiseContext& noise, kj::Own<kj::NetworkAddress> inner, const kj::Maybe<const NoisePeerIdentity&> peerIdentityM = nullptr) : noise(noise), inner(kj::mv(inner)), peerIdentityM(peerIdentityM) {}

    kj::String toString() override {
      return kj::str("noise:", this->inner->toString());
    }

    kj::Promise<kj::Own<kj::AsyncIoStream>> connect() override {
      return this->inner->connect()
        .then([this](auto stream) {
          return noise.wrapClient(kj::mv(stream), ""_kj);
        });
    }

    kj::Own<kj::ConnectionReceiver> listen() override {
      return noise.wrapPort(this->inner->listen());
    }

    kj::Own<kj::NetworkAddress> clone() override {
      return this->inner->clone();
    }

  private:
    NoiseContext& noise;
    kj::Own<kj::NetworkAddress> inner;
    const kj::Maybe<const NoisePeerIdentity&> peerIdentityM;
};

class NoiseNetwork final: public kj::Network {
  public:
    NoiseNetwork(NoiseContext& noise, kj::Network& inner) : noise(noise), inner(inner) {}

    kj::Promise<kj::Own<kj::NetworkAddress>> parseAddress(kj::StringPtr addr, uint portHint = 0) override {
      return this->inner.parseAddress(addr, portHint)
        .then([this](auto addr) -> kj::Own<kj::NetworkAddress> {
          return this->noise.wrapAddress(kj::mv(addr));
        });
    }

    kj::Own<kj::NetworkAddress> getSockaddr(const void* sockaddr, uint len) override {
      return this->inner.getSockaddr(sockaddr, len);
    }

    kj::Own<kj::Network> restrictPeers(
      kj::ArrayPtr<const kj::StringPtr> allow,
      kj::ArrayPtr<const kj::StringPtr> deny = nullptr) override {
      return this->inner.restrictPeers(allow, deny);
    }

  private:
    NoiseContext& noise;
    kj::Network& inner;
};

class FramedIoStream: public kj::AsyncIoStream {
  public:
    FramedIoStream(kj::Own<kj::AsyncIoStream> stream) : inner(kj::mv(stream)) {}

    kj::Promise<size_t> tryRead(void* buffer, size_t minBytes, size_t maxBytes) override {
      auto lengthBuffer = kj::heapArray<byte>(2);
      return this->inner->read(lengthBuffer.begin(), 2)
        .then([this, lengthBuffer = kj::mv(lengthBuffer), buffer]() mutable {
          const uint16_t length = lengthBuffer[0] << 8 | lengthBuffer[1];
          return this->inner->tryRead(buffer, length, length);
        });
    }

    kj::Promise<void> write(const void* buffer, size_t size) override {
      KJ_REQUIRE(size <= NOISE_MAX_PAYLOAD_LEN, "unable to write: provided buffer is too large");

      auto lengthBuffer = kj::heapArray<byte>(2);
      lengthBuffer[0] = (byte)(size >> 8);
      lengthBuffer[1] = (byte)size;

      auto piecesBuilder = kj::heapArrayBuilder<const ArrayPtr<const byte>>(2);
      piecesBuilder.add(lengthBuffer);
      piecesBuilder.add(kj::arrayPtr((byte*)buffer, size));
      auto pieces = piecesBuilder.finish();

      return this->inner->write(pieces).attach(kj::mv(pieces));
    }

    kj::Promise<void> write(ArrayPtr<const ArrayPtr<const byte>> pieces) override {
      auto piece = pieces.front();
      return this->write(piece.begin(), piece.size())
        .then([this, pieces]() -> kj::Promise<void> {
          if (pieces.size() > 1)
            return this->write(pieces.slice(1, pieces.size() - 1));
          return kj::READY_NOW;
        }).catch_([](kj::Exception&& exception) {
          KJ_LOG(ERROR, exception);
          kj::throwFatalException(kj::mv(exception));
        });
    }

    kj::Promise<void> whenWriteDisconnected() override {
      KJ_LOG(INFO, "FramedIoStream::whenWriteDisconnected()");
      return this->inner->whenWriteDisconnected();
    }

    void shutdownWrite() override {
      KJ_LOG(INFO, "FramedIoStream::shutdownWrite()");
      this->inner->shutdownWrite();
    }

  private:
    kj::Own<kj::AsyncIoStream> inner;
};

class NoiseConnection final: public kj::AsyncIoStream {
  public:
    NoiseConnection(kj::Own<kj::AsyncIoStream> stream,
      NoiseCipherState* sendState,
      NoiseCipherState* receiveState
    ) : inner(kj::mv(stream)),
        sendState(kj::Own<NoiseCipherState, CipherStateDisposer>(sendState)),
        receiveState(kj::Own<NoiseCipherState, CipherStateDisposer>(receiveState)) {}

    ~NoiseConnection() noexcept(false) { std::cout << "dtor" << std::endl; }

    kj::Promise<size_t> tryRead(void* buffer, size_t minBytes, size_t maxBytes) override {
      const size_t leftoverSize = this->leftoverBytes.size();
      if (leftoverSize > 0) {
        const size_t numBytesToCopy = leftoverSize > maxBytes ? maxBytes : leftoverSize;
        std::memcpy(buffer, this->leftoverBytes.begin(), numBytesToCopy);
        KJ_LOG(ERROR, "[memcpy/a numBytesToCopy]", minBytes, maxBytes, numBytesToCopy, this->leftoverBytes.size());
        this->leftoverBytes = kj::heapArray(this->leftoverBytes.slice(numBytesToCopy, leftoverSize - numBytesToCopy));

        if (numBytesToCopy > minBytes)
          return numBytesToCopy;
      }

      return this->inner->tryRead(this->readBuffer.begin(), 0, 0)
        .then([this, buffer, minBytes, maxBytes](size_t numBytesRead) mutable {
          NoiseBuffer noiseBuffer;
          noise_buffer_set_inout(noiseBuffer, this->readBuffer.begin(), numBytesRead, readBuffer.size());

          int err;
          err = noise_cipherstate_decrypt(this->receiveState, &noiseBuffer);
          if (err != NOISE_ERROR_NONE)
            noise_perror("unable to decrypt read buffer", err);

          if (noiseBuffer.size < minBytes) {
            std::memcpy(buffer, noiseBuffer.data, noiseBuffer.size);
            KJ_LOG(ERROR, "[memcpy/b noiseBuffer.size]", minBytes, maxBytes, noiseBuffer.size, this->leftoverBytes.size());
            const size_t parentNumBytesReturned = noiseBuffer.size;
            return this->tryRead((byte*)buffer + noiseBuffer.size, minBytes - noiseBuffer.size, maxBytes - noiseBuffer.size)
              .then([parentNumBytesReturned](size_t childNumBytesReturned) {
                return parentNumBytesReturned + childNumBytesReturned;
              }).catch_([](kj::Exception&& exception) {
                if (exception.getType() == kj::Exception::Type::DISCONNECTED) {
                  KJ_LOG(ERROR, exception);
                  kj::throwFatalException(kj::mv(exception));
                }
                return (size_t)0;
              });
          }

          if (noiseBuffer.size > maxBytes) {
            std::memcpy(buffer, noiseBuffer.data, maxBytes);
            this->leftoverBytes = kj::heapArray(noiseBuffer.data + maxBytes, noiseBuffer.size - maxBytes);
            KJ_LOG(ERROR, "[memcpy/c maxBytes]", minBytes, maxBytes, noiseBuffer.size, this->leftoverBytes.size());
            return kj::Promise<size_t>(maxBytes);
          } else {
            std::memcpy(buffer, noiseBuffer.data, noiseBuffer.size);
            KJ_LOG(ERROR, "[memcpy/d noiseBuffer.size]", minBytes, maxBytes, noiseBuffer.size, this->leftoverBytes.size());
            return kj::Promise<size_t>(noiseBuffer.size);
          }
        });
    }

    Promise<void> write(const void* buffer, size_t size) override {
      //auto data = encodeHex(kj::arrayPtr((byte*)buffer, size));
      //KJ_LOG(ERROR, "write()", data, size);

      const size_t macSize = noise_cipherstate_get_mac_length(this->sendState);
      auto noiseBufferBuilder = kj::heapArrayBuilder<byte>(size + macSize);
      noiseBufferBuilder.addAll((byte*)buffer, (byte*)buffer + size);
      KJ_LOG(ERROR, "addAll()", noiseBufferBuilder.size(), noiseBufferBuilder.capacity(), size);
      noiseBufferBuilder.resize(noiseBufferBuilder.capacity());
      auto noiseBuffer = noiseBufferBuilder.finish();

      NoiseBuffer bufferInfo;
      noise_buffer_set_inout(bufferInfo, noiseBuffer.begin(), size, noiseBuffer.size());

      int err;
      err = noise_cipherstate_encrypt(this->sendState, &bufferInfo);
      if (err != NOISE_ERROR_NONE)
        noise_perror("unable to encrypt write buffer", err);

      return this->inner->write((void*)noiseBuffer.begin(), noiseBuffer.size())
        .attach(kj::mv(noiseBuffer));
    }

    Promise<void> write(ArrayPtr<const ArrayPtr<const byte>> pieces) override {
      /*auto p = pieces.begin();
      while (p != pieces.end()) {
        auto data = encodeHex(kj::arrayPtr(p->begin(), p->size()));
        KJ_LOG(ERROR, "write2()", data);
        p++;
      }*/

      auto piece = pieces.front();
      return this->write(piece.begin(), piece.size())
        .then([this, pieces]() -> kj::Promise<void> {
          if (pieces.size() > 1)
            return this->write(pieces.slice(1, pieces.size() - 1));
          return kj::READY_NOW;
        }).catch_([](kj::Exception&& exception) {
          KJ_LOG(ERROR, exception);
          kj::throwFatalException(kj::mv(exception));
        });
      return kj::READY_NOW;
    }

    Promise<void> whenWriteDisconnected() override {
      KJ_LOG(INFO, "NoiseConnection::whenWriteDisconnected()");
      return this->inner->whenWriteDisconnected();
    }

    void shutdownWrite() override {
      KJ_LOG(INFO, "NoiseConnection::shutdownWrite()");
      this->inner->shutdownWrite();
    }

  private:
    class CipherStateDisposer {
      public:
        static void dispose(NoiseCipherState *ptr) {
          noise_cipherstate_free(ptr);
        }
    };

    kj::Own<kj::AsyncIoStream> inner;
    kj::Own<NoiseCipherState, CipherStateDisposer> sendState;
    kj::Own<NoiseCipherState, CipherStateDisposer> receiveState;
    kj::FixedArray<byte, NOISE_MAX_PAYLOAD_LEN> readBuffer;
    kj::Array<byte> leftoverBytes;
};

class NoiseHandshake {
  public:
    NoiseHandshake(NoiseContext& noise) : noise(noise) {}

    kj::Promise<kj::Own<NoiseConnection>> run(kj::Own<kj::AsyncIoStream> stream) {
      int err;
      NoiseHandshakeState* tmpState;

      err = noise_handshakestate_new_by_id(&tmpState, &this->noise.protocolId, this->noise.initiator ? NOISE_ROLE_INITIATOR : NOISE_ROLE_RESPONDER);
      if (err != NOISE_ERROR_NONE)
        noise_perror("unable to create handshake state", err);

      kj::Own<NoiseHandshakeState, HandshakeDisposer> state = kj::Own<NoiseHandshakeState, HandshakeDisposer>(tmpState);

      err = noise_handshakestate_start(state);
      if (err != NOISE_ERROR_NONE)
        noise_perror("unable to start handshake", err);

      kj::Own<HandshakeLoopParams> params = kj::heap<HandshakeLoopParams>();
      params->state = kj::mv(state);
      params->bufferArray = kj::heapArray<byte>(NOISE_MAX_PAYLOAD_LEN);
      params->stream = kj::heap<FramedIoStream>(kj::mv(stream));

      return this->runHandshakeLoop(kj::mv(params));
    }

  private:
    class HandshakeDisposer {
      public:
        static void dispose(NoiseHandshakeState *ptr) {
          noise_handshakestate_free(ptr);
        }
    };

    struct HandshakeLoopParams {
      kj::Own<NoiseHandshakeState, HandshakeDisposer> state;
      kj::Array<byte> bufferArray;
      kj::Own<kj::AsyncIoStream> stream;
      NoiseCipherState* sendState;
      NoiseCipherState* receiveState;
    };

    kj::Promise<kj::Own<NoiseConnection>> runHandshakeLoop(kj::Own<HandshakeLoopParams> params) {
      switch (noise_handshakestate_get_action(params->state)) {
        case NOISE_ACTION_WRITE_MESSAGE:
          NoiseBuffer buffer;
          int err;

          noise_buffer_set_output(buffer, params->bufferArray.begin(), params->bufferArray.size());
          err = noise_handshakestate_write_message(params->state, &buffer, nullptr);
          if (err != NOISE_ERROR_NONE)
            noise_perror("unable to write handshake response into buffer", err);

          return params->stream->write(buffer.data, buffer.size)
            .then([this, params = kj::mv(params)]() mutable {
              return this->runHandshakeLoop(kj::mv(params));
            });

        case NOISE_ACTION_READ_MESSAGE:
          return params->stream->tryRead(params->bufferArray.begin(), 0, 0)
            .then([this, params = kj::mv(params)](size_t length) mutable {
              NoiseBuffer buffer;
              int err;

              noise_buffer_set_input(buffer, params->bufferArray.begin(), length);
              err = noise_handshakestate_read_message(params->state, &buffer, nullptr);
              if (err != NOISE_ERROR_NONE)
                noise_perror("unable to read handshake into buffer", err);

              return this->runHandshakeLoop(kj::mv(params));
            });

        case NOISE_ACTION_SPLIT:
          NoiseCipherState* sendState;
          NoiseCipherState* receiveState;
          err = noise_handshakestate_split(params->state, &sendState, &receiveState);
          if (err != NOISE_ERROR_NONE)
            noise_perror("unable to complete handshake", err);

          params->sendState = sendState;
          params->receiveState = receiveState;

          return this->runHandshakeLoop(kj::mv(params));

        case NOISE_ACTION_COMPLETE:
          return kj::heap<NoiseConnection>(kj::mv(params->stream), params->sendState, params->receiveState);
      }

      kj::throwFatalException(KJ_EXCEPTION(FAILED, "invalid Noise action (this should never happen)"));
    }

    NoiseContext& noise;
};

class NoiseConnectionReceiver final: public ConnectionReceiver {
  public:
    NoiseConnectionReceiver(NoiseContext& noise, kj::Own<kj::ConnectionReceiver> inner) : noise(noise), inner(kj::mv(inner)) {}

    kj::Promise<kj::Own<kj::AsyncIoStream>> accept() override {
      return this->inner->accept()
        .then([this](auto stream) {
          auto handshake = kj::heap<NoiseHandshake>(this->noise);
          return handshake->run(kj::mv(stream));
        }).then([](kj::Own<kj::AsyncIoStream> nc) { return nc; });
    }

    uint getPort() override {
      return this->inner->getPort();
    }

  private:
    NoiseContext& noise;
    kj::Own<ConnectionReceiver> inner;

};

kj::Own<NoisePeerIdentity> NoisePeerIdentity::newInstance(const kj::StringPtr identityStr) {
  return kj::heap<NoisePeerIdentityImpl>(identityStr);
}

NoiseContext::NoiseContext(bool initiator, const kj::StringPtr protocol, kj::Maybe<kj::Own<const SecretKey<Curve25519>>> localIdentityM) : initiator(initiator), localIdentityM(kj::mv(localIdentityM)) {
  noise_protocol_name_to_id(&this->protocolId, protocol.cStr(), protocol.size());
}

kj::Promise<kj::Own<kj::AsyncIoStream>> NoiseContext::wrapServer(kj::Own<kj::AsyncIoStream> stream) {
  kj::throwFatalException(KJ_EXCEPTION(FAILED, "not implemented"));
}

kj::Promise<kj::Own<kj::AsyncIoStream>> NoiseContext::wrapClient(kj::Own<kj::AsyncIoStream> stream, kj::StringPtr expectedPeerIdentityStr) {
  auto handshake = kj::heap<NoiseHandshake>(*this);
  return handshake->run(kj::mv(stream))
    .then([](kj::Own<kj::AsyncIoStream> nc) { return nc; });
}

kj::Own<kj::NetworkAddress> NoiseContext::wrapAddress(kj::Own<kj::NetworkAddress> address, const kj::Maybe<const kj::NoisePeerIdentity&> expectedPeerIdentityM) {
  return kj::heap<NoiseNetworkAddress>(*this, kj::mv(address), expectedPeerIdentityM);
}

kj::Own<kj::Network> NoiseContext::wrapNetwork(kj::Network& network) {
  return kj::heap<NoiseNetwork>(*this, network);
}

kj::Own<kj::ConnectionReceiver> NoiseContext::wrapPort(kj::Own<kj::ConnectionReceiver> port) {
  return kj::heap<NoiseConnectionReceiver>(*this, kj::mv(port));
}

}
