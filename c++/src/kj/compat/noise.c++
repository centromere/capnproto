#include <cstring>
#include <iostream>

#include <kj/debug.h>
#include <kj/encoding.h>

#include "noise.h"

namespace kj {

namespace {

class NoisePeerIdentityImpl final: public NoisePeerIdentity {
  public:
    NoisePeerIdentityImpl(const Curve25519Key& publicKey, bool transmit) : publicKey(publicKey), transmit(transmit) {}
    NoisePeerIdentityImpl(const kj::StringPtr publicKey, bool transmit) : transmit(transmit) {
      auto decoded = decodeBase64(publicKey);
      KJ_REQUIRE(decoded.size() == 32, "Base64-decoded Noise public key is not exactly 32 bytes");
      std::memcpy(this->publicKey.begin(), decoded.begin(), 32);
    }

    kj::String toString() override {
      return encodeBase64(this->publicKey);
    }

  private:
    Curve25519Key publicKey;
    bool transmit;
};

}  // namespace

class NoiseNetworkAddress final: public kj::NetworkAddress {
  public:
    NoiseNetworkAddress(NoiseContext& noise, kj::Own<kj::NetworkAddress> inner, kj::Maybe<kj::Own<NoisePeerIdentity>> peerIdentityM = nullptr) : noise(noise), inner(kj::mv(inner)), peerIdentityM(kj::mv(peerIdentityM)) {}

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
    kj::Maybe<kj::Own<NoisePeerIdentity>> peerIdentityM;
};

class NoiseNetwork final: public kj::Network {
  public:
    NoiseNetwork(NoiseContext& noise, kj::Network& inner) : noise(noise), inner(inner) {}

    kj::Promise<kj::Own<kj::NetworkAddress>> parseAddress(kj::StringPtr addr, uint portHint = 0) override {
      return this->inner.parseAddress(addr, portHint)
        .then([this](auto addr) -> kj::Own<kj::NetworkAddress> {
          return this->noise.wrapAddress(kj::mv(addr), (kj::Maybe<kj::NoisePeerIdentity&>)nullptr);
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
    NoiseConnection(NoiseContext &noise, int role, kj::Own<kj::AsyncIoStream> stream) : noise(noise), inner(kj::mv(stream)) {
      int err;
      NoiseHandshakeState* handshakePtr;
      err = noise_handshakestate_new_by_name(&handshakePtr, "Noise_NN_25519_ChaChaPoly_BLAKE2s", role);
      if (err != NOISE_ERROR_NONE) {
        noise_perror("unable to create handshake", err);
      }

      this->handshake = kj::Own<NoiseHandshakeState, HandshakeDisposer>(handshakePtr);

      err = noise_handshakestate_start(this->handshake);
      if (err != NOISE_ERROR_NONE) {
        noise_perror("unable to start handshake", err);
      }

      this->readBuffer = kj::heapArray<byte>(NOISE_MAX_PAYLOAD_LEN);
      this->writeBuffer = kj::heapArray<byte>(NOISE_MAX_PAYLOAD_LEN);
    }

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

    void shutdownWrite() override {
    }

  private:
    class HandshakeDisposer {
      public:
        static void dispose(NoiseHandshakeState *ptr) {
          noise_handshakestate_free(ptr);
        }
    };

    NoiseContext& noise;
    kj::Own<kj::AsyncIoStream> inner;
    kj::Own<NoiseHandshakeState, HandshakeDisposer> handshake;
    kj::Array<byte> readBuffer;
    kj::Array<byte> writeBuffer;
};

class NoiseConnectionReceiver final: public ConnectionReceiver {
  public:
    NoiseConnectionReceiver(NoiseContext& noise, kj::Own<kj::ConnectionReceiver> inner) : noise(noise), inner(kj::mv(inner)) {}

    kj::Promise<kj::Own<kj::AsyncIoStream>> accept() override {
      return this->inner->accept()
        .then([](auto stream) {
          std::cout << "connection received" << std::endl;
          return stream;

          /*NoiseHandshakeState *hstate;

          return stream->tryRead(readBuffer.begin(), 32, 32)
            .then([hstate, readBuffer = kj::mv(readBuffer)](size_t numBytesRead) mutable {
              std::cout << "read " << numBytesRead << " bytes" << std::endl;

              NoiseBuffer buf;
              noise_buffer_set_input(buf, readBuffer.begin(), 32);
              err = noise_handshakestate_read_message(hstate, &buf, nullptr);
              if (err != NOISE_ERROR_NONE) {
                noise_perror("unable to complete handshake", err);
              }

              if (noise_handshakestate_get_action(hstate) == NOISE_ACTION_WRITE_MESSAGE) {
                std::cout << "write response" << std::endl;
              } else {
                std::cout << "not sure what to do here" << std::endl;
              }

              return hstate;
            }).then([stream = kj::mv(stream), writeBuffer = kj::mv(writeBuffer)](auto hstate) mutable {
              int err;
              NoiseBuffer buf;
              noise_buffer_set_output(buf, writeBuffer.begin(), writeBuffer.size());
              err = noise_handshakestate_write_message(hstate, &buf, nullptr);
              if (err != NOISE_ERROR_NONE) {
                noise_perror("unable to write handshake response in to buffer", err);
              }

              return stream->write(buf.data, buf.size)
                .then([stream = kj::mv(stream)]() mutable { return kj::mv(stream); });
            }).then([](auto stream) mutable -> kj::Own<kj::AsyncIoStream> {
              return kj::heap<NoiseConnection>(kj::mv(stream));
            });*/
        });
    }

    uint getPort() override {
      return this->inner->getPort();
    }

  private:
    NoiseContext& noise;
    kj::Own<ConnectionReceiver> inner;
};

kj::Own<NoisePeerIdentity> NoisePeerIdentity::newInstance(const Curve25519Key& publicKey, bool transmit) {
  return kj::heap<NoisePeerIdentityImpl>(publicKey, transmit);
}

kj::Own<NoisePeerIdentity> NoisePeerIdentity::newInstance(const kj::StringPtr publicKey, bool transmit) {
  return kj::heap<NoisePeerIdentityImpl>(publicKey, transmit);
}

NoiseContext::NoiseContext(kj::Maybe<kj::StringPtr> localStaticKeyStrM) {
  KJ_IF_MAYBE(localStaticKeyStr, localStaticKeyStrM) {
    auto decoded = decodeBase64(*localStaticKeyStr);
    KJ_REQUIRE(decoded.size() == 32, "Base64-decoded Noise private key is not exactly 32 bytes");
    Curve25519Key k;
    std::memcpy(k.begin(), decoded.begin(), 32);
    this->localStaticKeyM.emplace(k);
  }

  this->protocol.cipher_id = NOISE_CIPHER_CHACHAPOLY;
  this->protocol.dh_id = NOISE_DH_CURVE25519;
  this->protocol.hash_id = NOISE_HASH_BLAKE2s;
}

kj::Promise<kj::Own<kj::AsyncIoStream>> NoiseContext::wrapServer(kj::Own<kj::AsyncIoStream> stream) {
  return kj::Promise<kj::Own<kj::AsyncIoStream>>(kj::heap<NoiseConnection>(*this, NOISE_ROLE_RESPONDER, kj::mv(stream)));
}

kj::Own<kj::NetworkAddress> NoiseContext::wrapAddress(kj::Own<kj::NetworkAddress> address, kj::Maybe<kj::NoisePeerIdentity&> expectedPeerIdentity) {
  /*if (expectedServerHostname.size() > 0) {
    kj::Maybe<kj::Own<NoisePeerIdentity>> npiM = NoisePeerIdentity::newInstance(expectedServerHostname);
    return kj::heap<NoiseNetworkAddress>(*this, kj::mv(address), kj::mv(npiM));
  } else {
    return kj::heap<NoiseNetworkAddress>(*this, kj::mv(address));
  }*/
}

kj::Own<kj::Network> NoiseContext::wrapNetwork(kj::Network& network) {
  return kj::heap<NoiseNetwork>(*this, network);
}

kj::Own<kj::ConnectionReceiver> NoiseContext::wrapPort(kj::Own<kj::ConnectionReceiver> port) {
  return kj::heap<NoiseConnectionReceiver>(*this, kj::mv(port));
}

}
