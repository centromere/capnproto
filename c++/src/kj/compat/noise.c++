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

class NoiseConnection final: public kj::AsyncIoStream {
  public:
    NoiseConnection(kj::Own<kj::AsyncIoStream> stream,
      NoiseCipherState* sendState,
      NoiseCipherState* receiveState
    ) : inner(kj::mv(stream)),
        sendState(kj::Own<NoiseCipherState, CipherStateDisposer>(sendState)),
        receiveState(kj::Own<NoiseCipherState, CipherStateDisposer>(receiveState)) {}

    kj::Promise<size_t> tryRead(void* buffer, size_t minBytes, size_t maxBytes) override {
      const size_t leftoverSize = this->leftoverBytes.size();
      if (leftoverSize >= minBytes) {
        size_t numBytesRead = leftoverSize > maxBytes ? maxBytes : leftoverSize;
        std::memcpy(buffer, this->leftoverBytes.begin(), numBytesRead);
        this->leftoverBytes = kj::heapArray(this->leftoverBytes.slice(numBytesRead, numBytesRead + (leftoverSize - numBytesRead)));
        return numBytesRead;
      }

      auto lengthBuffer = kj::heapArray<byte>(2);
      return this->inner->read(lengthBuffer.begin(), 2)
        .then([this, lengthBuffer = kj::mv(lengthBuffer)]() mutable {
          const uint16_t length = lengthBuffer[0] << 8 | lengthBuffer[1];

          auto readBuffer = kj::heapArray<byte>(length);
          return this->inner->read((void*)readBuffer.begin(), length, length)
            .then([readBuffer = kj::mv(readBuffer)](size_t numBytesRead) mutable { return kj::tuple(numBytesRead, kj::mv(readBuffer)); });
        }).then([this, buffer, minBytes, maxBytes](auto result) mutable {
          size_t numBytesRead = kj::get<0>(result);
          kj::Array<byte> readBuffer = kj::mv(kj::get<1>(result));

          int err;
          NoiseBuffer noiseBuffer;

          noise_buffer_set_inout(noiseBuffer, readBuffer.begin(), numBytesRead, readBuffer.size());
          err = noise_cipherstate_decrypt(this->receiveState, &noiseBuffer);
          if (err != NOISE_ERROR_NONE)
            noise_perror("unable to decrypt read buffer", err);

          if (noiseBuffer.size < minBytes)
            return this->tryRead(readBuffer.begin() + noiseBuffer.size, minBytes - noiseBuffer.size, maxBytes - noiseBuffer.size);

          if (noiseBuffer.size < maxBytes) {
            std::memcpy(buffer, noiseBuffer.data, noiseBuffer.size);
            return kj::Promise<size_t>(noiseBuffer.size);
          } else {
            std::memcpy(buffer, noiseBuffer.data, maxBytes);
            this->leftoverBytes = kj::heapArray(noiseBuffer.data + maxBytes, noiseBuffer.size - maxBytes);
            return kj::Promise<size_t>(maxBytes);
          }
        });
    }

    Promise<void> write(const void* buffer, size_t size) override {
      const size_t macSize = noise_cipherstate_get_mac_length(this->sendState);
      const size_t numChunks = (size / NOISE_MAX_PAYLOAD_LEN) + 1;
      const size_t overhead = (2 + macSize) * numChunks; // 2-byte framing and MAC

      auto builder = kj::heapArrayBuilder<byte>(size + overhead);
      auto bufferInfoBuilder = kj::heapArrayBuilder<NoiseBuffer>(numChunks);

      byte* bufferPtr = (byte*)buffer;
      size_t remaining = size;
      size_t chunkSize;
      NoiseBuffer bufferInfo;

      while (remaining > 0) {
        builder.resize(builder.size() + 2);

        chunkSize = remaining > NOISE_MAX_PAYLOAD_LEN - macSize ? NOISE_MAX_PAYLOAD_LEN - macSize : remaining;
        noise_buffer_set_inout(bufferInfo, builder.end(), chunkSize, chunkSize + macSize);
        builder.addAll(bufferPtr, bufferPtr + chunkSize);
        builder.resize(builder.size() + macSize);

        bufferPtr += chunkSize;
        remaining -= chunkSize;
        bufferInfoBuilder.add(bufferInfo);
      }

      auto noiseBuffer = builder.finish();
      auto bufferInfos = bufferInfoBuilder.finish().attach(kj::mv(noiseBuffer));

      return this->writeInternal(kj::mv(bufferInfos), 0);
    }

    Promise<void> writeInternal(kj::Array<NoiseBuffer> bufferInfos, size_t position) {
      if (position < bufferInfos.size()) {
        NoiseBuffer& currentBuffer = bufferInfos[position];
        int err;
        err = noise_cipherstate_encrypt(this->sendState, &currentBuffer);
        if (err != NOISE_ERROR_NONE)
          noise_perror("unable to encrypt write buffer", err);

        currentBuffer.data[-2] = (byte)(currentBuffer.size >> 8);
        currentBuffer.data[-1] = (byte)currentBuffer.size;

        return this->inner->write(currentBuffer.data - 2, currentBuffer.size + 2)
          .then([this, bufferInfos = kj::mv(bufferInfos), position]() mutable {
            return this->writeInternal(kj::mv(bufferInfos), position + 1);
          });
      }

      return kj::READY_NOW;
    }

    Promise<void> write(ArrayPtr<const ArrayPtr<const byte>> pieces) override {
      kj::throwFatalException(KJ_EXCEPTION(FAILED, "not implemented"));
      return kj::READY_NOW;
    }

    Promise<void> whenWriteDisconnected() override {
      return kj::READY_NOW;
    }

    void shutdownWrite() override {}

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

      // Plus two bytes for framing.
      kj::Array<byte> bufferArray = kj::heapArray<byte>(NOISE_MAX_PAYLOAD_LEN + 2);

      kj::Own<HandshakeLoopParams> params = kj::heap<HandshakeLoopParams>();
      params->state = kj::mv(state);
      params->bufferArray = kj::mv(bufferArray);
      params->stream = kj::mv(stream);

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

          noise_buffer_set_output(buffer, params->bufferArray.begin() + 2, params->bufferArray.size() - 2);
          err = noise_handshakestate_write_message(params->state, &buffer, nullptr);
          if (err != NOISE_ERROR_NONE)
            noise_perror("unable to write handshake response into buffer", err);

          buffer.data -= 2;
          buffer.data[0] = (uint8_t)(buffer.size >> 8);
          buffer.data[1] = (uint8_t)buffer.size;
          buffer.size += 2;

          return params->stream->write(buffer.data, buffer.size)
            .then([this, params = kj::mv(params)]() mutable {
              return this->runHandshakeLoop(kj::mv(params));
            });

        case NOISE_ACTION_READ_MESSAGE:
          return params->stream->read(params->bufferArray.begin(), 2)
            .then([params = kj::mv(params)]() mutable {
                const uint16_t length = params->bufferArray[0] << 8 | params->bufferArray[1];
                return params->stream->read(params->bufferArray.begin(), length)
                  .then([length, params = kj::mv(params)]() mutable {
                    return kj::tuple(kj::mv(params), length);
                  });
            }).then([this](auto result) mutable {
              NoiseBuffer buffer;
              int err;
              auto params = kj::mv(kj::get<0>(result));
              auto length = kj::get<1>(result);

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
