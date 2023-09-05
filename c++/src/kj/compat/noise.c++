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
      return this->inner->connect();
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
    NoiseConnection(kj::Own<kj::AsyncIoStream> stream) : inner(kj::mv(stream)) {}

    kj::Promise<size_t> tryRead(void* buffer, size_t minBytes, size_t maxBytes) override {
      return this->inner->tryRead(buffer, minBytes, maxBytes);
    }

    Promise<void> write(const void* buffer, size_t size) override {
      return kj::READY_NOW;
    }

    Promise<void> write(ArrayPtr<const ArrayPtr<const byte>> pieces) override {
      return kj::READY_NOW;
    }

    Promise<void> whenWriteDisconnected() override {
      return kj::READY_NOW;
    }

    void shutdownWrite() override {}

  private:
    kj::Own<kj::AsyncIoStream> inner;
};

class NoiseConnectionReceiver final: public ConnectionReceiver {
  public:
    NoiseConnectionReceiver(const NoiseContext& noise, kj::Own<kj::ConnectionReceiver> inner) : noise(noise), inner(kj::mv(inner)) {}

    kj::Promise<kj::Own<kj::AsyncIoStream>> accept() override {
      return this->inner->accept()
        .then([this](auto stream) {
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
        }).then([](auto stream) mutable -> kj::Own<kj::AsyncIoStream> {
          return kj::heap<NoiseConnection>(kj::mv(stream));
        });
    }

    uint getPort() override {
      return this->inner->getPort();
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
    };

    kj::Promise<kj::Own<kj::AsyncIoStream>> runHandshakeLoop(kj::Own<HandshakeLoopParams> params) {
      std::cout << "a" << std::endl;
      switch (noise_handshakestate_get_action(params->state)) {
        case NOISE_ACTION_WRITE_MESSAGE:
          NoiseBuffer buffer;
          int err;

          noise_buffer_set_output(buffer, params->bufferArray.begin() + 2, params->bufferArray.size() - 2);
          err = noise_handshakestate_write_message(params->state, &buffer, nullptr);
          if (err != NOISE_ERROR_NONE)
            noise_perror("unable to write handshake response into buffer", err);

          noise_buffer_set_output(buffer, params->bufferArray.begin(), buffer.size + 2);
          buffer.data[0] = (uint8_t)buffer.size >> 8;
          buffer.data[1] = (uint8_t)buffer.size;

          std::cout << "b" << std::endl;
          return params->stream->write(buffer.data, buffer.size)
            .then([this, params = kj::mv(params)]() mutable {
              return this->runHandshakeLoop(kj::mv(params));
            });

        case NOISE_ACTION_READ_MESSAGE:
          std::cout << "c" << std::endl;
          return params->stream->read(params->bufferArray.begin(), 2)
            .then([params = kj::mv(params)]() mutable {
                const uint16_t length = params->bufferArray[0] << 8 | params->bufferArray[1];
                std::cout << "f: " << length << std::endl;
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
                noise_perror("unable to complete handshake", err);

              std::cout << "d" << std::endl;
              return this->runHandshakeLoop(kj::mv(params));
            });
      }

      std::cout << "e" << std::endl;
      return kj::mv(params->stream);
    }

    const NoiseContext& noise;
    kj::Own<ConnectionReceiver> inner;

};

kj::Own<NoisePeerIdentity> NoisePeerIdentity::newInstance(const kj::StringPtr identityStr) {
  return kj::heap<NoisePeerIdentityImpl>(identityStr);
}

NoiseContext::NoiseContext(bool initiator, const kj::StringPtr protocol, kj::Maybe<kj::Own<const SecretKey<Curve25519>>> localIdentityM) : initiator(initiator), localIdentityM(kj::mv(localIdentityM)) {
  noise_protocol_name_to_id(&this->protocolId, protocol.cStr(), protocol.size());
}

kj::Promise<kj::Own<kj::AsyncIoStream>> NoiseContext::wrapServer(kj::Own<kj::AsyncIoStream> stream) {
  return kj::Promise<kj::Own<kj::AsyncIoStream>>(kj::heap<NoiseConnection>(kj::mv(stream)));
}

kj::Promise<kj::Own<kj::AsyncIoStream>> NoiseContext::wrapClient(kj::Own<kj::AsyncIoStream> stream, kj::StringPtr expectedPeerIdentityStr) {
  return kj::Promise<kj::Own<kj::AsyncIoStream>>(kj::heap<NoiseConnection>(kj::mv(stream)));
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
