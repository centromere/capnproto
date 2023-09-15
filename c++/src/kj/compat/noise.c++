#include <iostream>

#include <kj/debug.h>
#include <kj/encoding.h>
#include <kj/string-tree.h>

#include "noise/noise-c/include/noise/protocol.h"
#include "noise.h"

namespace kj {

int X25519::algorithmId() { return NOISE_DH_CURVE25519; }

template <typename DH>
SecretKey<DH>::SecretKey(const StringPtr secretData) : PublicKey<DH>(), secretData(secretData) {
  NoiseDHState* state;
  noise_dhstate_new_by_id(&state, DH::algorithmId());
  noise_dhstate_set_keypair_private(state, this->secretData.begin(), this->secretData.size());
  noise_dhstate_get_public_key(state, this->publicData.begin(), this->publicData.size());
}

template class SecretKey<X25519>;

namespace {

class NoisePeerIdentityImpl final: public NoisePeerIdentity {
  public:
    NoisePeerIdentityImpl(const StringPtr identityStr) : key(identityStr) {}

    String toString() override {
      return str(this->key.getPublicData().asBase64());
    }

  private:
    const PublicKey<X25519> key;
};

}  // namespace

class NoiseMessageStream final: public AsyncIoMessageStream {
  public:
    NoiseMessageStream(Own<AsyncIoStream> inner) : inner(mv(inner)) {}

    Promise<Maybe<Array<byte>>> tryReadMessage() override {
      auto lengthBuffer = heapArray<byte>(2);
      KJ_LOG(ERROR, "reading 2");
      return this->inner->read(lengthBuffer.begin(), 2)
        .then([this, lengthBuffer = mv(lengthBuffer)]() {
          const uint16_t length = lengthBuffer[0] << 8 | lengthBuffer[1];
          KJ_LOG(ERROR, "reading", length);
          auto buffer = heapArray<byte>(length);
          return this->inner->tryRead((void*)buffer.begin(), length, length)
            .then([buffer = mv(buffer)](auto numBytesRead) mutable {
              return tuple(numBytesRead, mv(buffer));
            });
        }).then([](auto result) -> Maybe<Array<byte>> {
          size_t numBytesRead = get<0>(result);
          Array<byte> buffer = mv(get<1>(result));
          if (numBytesRead != buffer.size())
            return nullptr;
          else
            return mv(buffer);
        });
    };

    Promise<void> writeMessage(const ArrayPtr<const byte> msg) override {
      KJ_REQUIRE(msg.size() <= NOISE_MAX_PAYLOAD_LEN, "unable to write: provided buffer is too large");

      auto lengthBuffer = heapArray<byte>(2);
      lengthBuffer[0] = (byte)(msg.size() >> 8);
      lengthBuffer[1] = (byte)msg.size();

      auto piecesBuilder = heapArrayBuilder<const ArrayPtr<const byte>>(2);
      piecesBuilder.add(lengthBuffer);
      piecesBuilder.add(msg);
      auto pieces = piecesBuilder.finish();

      return this->inner->write(pieces).attach(mv(lengthBuffer));
    }

  private:
    Own<AsyncIoStream> inner;
};

class NoiseConnection final: public AsyncIoMessageStream {
  public:
    NoiseConnection(Own<AsyncIoMessageStream> inner, NoiseCipherState* sendState, NoiseCipherState* receiveState) :
      inner(mv(inner)),
      sendState(Own<NoiseCipherState, CipherStateDisposer>(sendState)),
      receiveState(Own<NoiseCipherState, CipherStateDisposer>(receiveState)) {}

    Promise<Maybe<Array<byte>>> tryReadMessage() override {
      return this->inner->tryReadMessage()
        .then([this](auto msgM) mutable -> Maybe<Array<byte>> {
          auto& msg = KJ_ASSERT_NONNULL(msgM, "failed to receive message");

          NoiseBuffer noiseBuffer;
          noise_buffer_set_inout(noiseBuffer, msg.begin(), msg.size(), msg.size());

          int err;
          err = noise_cipherstate_decrypt(this->receiveState, &noiseBuffer);
          if (err != NOISE_ERROR_NONE)
            noise_perror("unable to decrypt read buffer", err);

          auto b = arrayPtr<byte>(noiseBuffer.data, noiseBuffer.size);
          auto c = encodeHex(b);
          KJ_LOG(ERROR, "read buffer", c);
          return kj::heapArray(arrayPtr(noiseBuffer.data, noiseBuffer.size));
        });
    }

    Promise<void> writeMessage(const ArrayPtr<const byte> msg) override {
      auto b = encodeHex(msg);
      KJ_LOG(ERROR, "write buffer", b);

      const size_t macSize = noise_cipherstate_get_mac_length(this->sendState);
      auto noiseBufferBuilder = heapArrayBuilder<byte>(msg.size() + macSize);
      noiseBufferBuilder.addAll(msg);
      noiseBufferBuilder.resize(noiseBufferBuilder.capacity());
      auto noiseBuffer = noiseBufferBuilder.finish();

      NoiseBuffer bufferInfo;
      noise_buffer_set_inout(bufferInfo, noiseBuffer.begin(), msg.size(), noiseBuffer.size());

      int err;
      err = noise_cipherstate_encrypt(this->sendState, &bufferInfo);
      if (err != NOISE_ERROR_NONE)
        noise_perror("unable to encrypt write buffer", err);

      return this->inner->writeMessage(noiseBuffer)
        .attach(mv(noiseBuffer));
    }

    /*Promise<void> whenWriteDisconnected() override {}
      KJ_LOG(INFO, "NoiseConnection::whenWriteDisconnected()");
      return this->inner->whenWriteDisconnected();
    }

    void shutdownWrite() override {}
      KJ_LOG(INFO, "NoiseConnection::shutdownWrite()");
      this->inner->shutdownWrite();
    }*/

  private:
    class CipherStateDisposer {
      public:
        static void dispose(NoiseCipherState *ptr) {
          noise_cipherstate_free(ptr);
        }
    };

    Own<AsyncIoMessageStream> inner;
    Own<NoiseCipherState, CipherStateDisposer> sendState;
    Own<NoiseCipherState, CipherStateDisposer> receiveState;
};

class NoiseHandshake {
  public:
    NoiseHandshake(NoiseContext& noise) : noise(noise) {}

    Promise<Own<NoiseConnection>> run(Own<AsyncIoMessageStream> stream) {
      int err;
      NoiseHandshakeState* tmpState;

      err = noise_handshakestate_new_by_id(&tmpState, (const NoiseProtocolId*)this->noise.protocolId.get(), this->noise.initiator ? NOISE_ROLE_INITIATOR : NOISE_ROLE_RESPONDER);
      if (err != NOISE_ERROR_NONE)
        noise_perror("unable to create handshake state", err);

      Own<NoiseHandshakeState, HandshakeDisposer> state = Own<NoiseHandshakeState, HandshakeDisposer>(tmpState);

      err = noise_handshakestate_start(state);
      if (err != NOISE_ERROR_NONE)
        noise_perror("unable to start handshake", err);

      Own<HandshakeLoopParams> params = heap<HandshakeLoopParams>();
      params->state = mv(state);
      params->bufferArray = heapArray<byte>(NOISE_MAX_PAYLOAD_LEN);
      params->stream = mv(stream);

      return this->runHandshakeLoop(mv(params));
    }

  private:
    class HandshakeDisposer {
      public:
        static void dispose(NoiseHandshakeState *ptr) {
          noise_handshakestate_free(ptr);
        }
    };

    struct HandshakeLoopParams {
      Own<NoiseHandshakeState, HandshakeDisposer> state;
      Array<byte> bufferArray;
      Own<AsyncIoMessageStream> stream;
      NoiseCipherState* sendState;
      NoiseCipherState* receiveState;
    };

    Promise<Own<NoiseConnection>> runHandshakeLoop(Own<HandshakeLoopParams> params) {
      switch (noise_handshakestate_get_action(params->state)) {
        case NOISE_ACTION_WRITE_MESSAGE:
          NoiseBuffer buffer;
          int err;

          noise_buffer_set_output(buffer, params->bufferArray.begin(), params->bufferArray.size());
          err = noise_handshakestate_write_message(params->state, &buffer, nullptr);
          if (err != NOISE_ERROR_NONE)
            noise_perror("unable to write handshake response into buffer", err);

          return params->stream->writeMessage(arrayPtr(buffer.data, buffer.size))
            .then([this, params = mv(params)]() mutable {
              return this->runHandshakeLoop(mv(params));
            });

        case NOISE_ACTION_READ_MESSAGE:
          return params->stream->tryReadMessage()
            .then([this, params = mv(params)](Maybe<Array<byte>> msgM) mutable {
              auto& msg = KJ_ASSERT_NONNULL(msgM, "connection shutdown");
              NoiseBuffer buffer;
              int err;

              noise_buffer_set_input(buffer, msg.begin(), msg.size());
              err = noise_handshakestate_read_message(params->state, &buffer, nullptr);
              if (err != NOISE_ERROR_NONE)
                noise_perror("unable to read handshake into buffer", err);

              return this->runHandshakeLoop(mv(params));
            });

        case NOISE_ACTION_SPLIT:
          NoiseCipherState* sendState;
          NoiseCipherState* receiveState;
          err = noise_handshakestate_split(params->state, &sendState, &receiveState);
          if (err != NOISE_ERROR_NONE)
            noise_perror("unable to complete handshake", err);

          params->sendState = sendState;
          params->receiveState = receiveState;

          return this->runHandshakeLoop(mv(params));

        case NOISE_ACTION_COMPLETE:
          return heap<NoiseConnection>(mv(params->stream), params->sendState, params->receiveState);
      }

      throwFatalException(KJ_EXCEPTION(FAILED, "invalid Noise action (this should never happen)"));
    }

    NoiseContext& noise;
};

class NoiseNetworkAddress final: public NetworkAddress {
  public:
    NoiseNetworkAddress(NoiseContext& noise, Own<NetworkAddress> inner, const Maybe<const NoisePeerIdentity&> peerIdentityM = nullptr) : noise(noise), inner(mv(inner)), peerIdentityM(peerIdentityM) {}

    String toString() override {
      return str("noise:", this->inner->toString());
    }

    Promise<Own<AsyncIoStream>> connect() override {
      KJ_UNIMPLEMENTED("accept() not implemented for NoiseNetworkAddress");
    }

    Promise<Own<AsyncIoMessageStream>> connectMsg() override {
      return this->inner->connect()
        .then([this](auto stream) {
          auto handshake = heap<NoiseHandshake>(this->noise);
          return handshake->run(heap<NoiseMessageStream>(mv(stream)))
            .then([](Own<AsyncIoMessageStream> nc) { return nc; });
        });
    }

    Own<ConnectionReceiver> listen() override {
      return noise.wrapPort(this->inner->listen());
    }

    Own<NetworkAddress> clone() override {
      return this->inner->clone();
    }

  private:
    NoiseContext& noise;
    Own<NetworkAddress> inner;
    const Maybe<const NoisePeerIdentity&> peerIdentityM;
};

class NoiseNetwork final: public Network {
  public:
    NoiseNetwork(NoiseContext& noise, Network& inner) : noise(noise), inner(inner) {}

    Promise<Own<NetworkAddress>> parseAddress(StringPtr addr, uint portHint = 0) override {
      return this->inner.parseAddress(addr, portHint)
        .then([this](auto addr) -> Own<NetworkAddress> {
          return this->noise.wrapAddress(mv(addr));
        });
    }

    Own<NetworkAddress> getSockaddr(const void* sockaddr, uint len) override {
      return this->inner.getSockaddr(sockaddr, len);
    }

    Own<Network> restrictPeers(
      ArrayPtr<const StringPtr> allow,
      ArrayPtr<const StringPtr> deny = nullptr) override {
      return this->inner.restrictPeers(allow, deny);
    }

  private:
    NoiseContext& noise;
    Network& inner;
};

class NoiseConnectionReceiver final: public ConnectionReceiver {
  public:
    NoiseConnectionReceiver(NoiseContext& noise, Own<ConnectionReceiver> inner) : noise(noise), inner(mv(inner)) {}

    Promise<Own<AsyncIoStream>> accept() override {
      KJ_UNIMPLEMENTED("accept() not implemented for NoiseConnectionReceiver");
    }

    Promise<Own<AsyncIoMessageStream>> acceptMsg() override {
      return this->inner->accept()
        .then([this](auto stream) -> Promise<Own<NoiseConnection>> {
          auto handshake = heap<NoiseHandshake>(this->noise);
          return handshake->run(heap<NoiseMessageStream>(mv(stream)));
        }).then([](Own<NoiseConnection> nc) -> Own<AsyncIoMessageStream> { return nc; });
    }

    uint getPort() override {
      return this->inner->getPort();
    }

  private:
    NoiseContext& noise;
    Own<ConnectionReceiver> inner;
};

Own<NoisePeerIdentity> NoisePeerIdentity::newInstance(const StringPtr identityStr) {
  return heap<NoisePeerIdentityImpl>(identityStr);
}

NoiseContext::NoiseContext(bool initiator, const StringPtr protocol, Maybe<Own<const SecretKey<X25519>>> localIdentityM) : initiator(initiator), localIdentityM(mv(localIdentityM)) {
  this->protocolId = heap<NoiseProtocolId>();
  noise_protocol_name_to_id((NoiseProtocolId*)this->protocolId.get(), protocol.cStr(), protocol.size());
}

Promise<Own<AsyncIoStream>> NoiseContext::wrapServer(Own<AsyncIoStream> stream) {
  throwFatalException(KJ_EXCEPTION(FAILED, "not implemented"));
}

Promise<Own<AsyncIoStream>> NoiseContext::wrapClient(Own<AsyncIoStream> stream, StringPtr expectedPeerIdentityStr) {
  throwFatalException(KJ_EXCEPTION(FAILED, "not implemented"));
}

Own<NetworkAddress> NoiseContext::wrapAddress(Own<NetworkAddress> address, const Maybe<const NoisePeerIdentity&> expectedPeerIdentityM) {
  return heap<NoiseNetworkAddress>(*this, mv(address), expectedPeerIdentityM);
}

Own<Network> NoiseContext::wrapNetwork(Network& network) {
  return heap<NoiseNetwork>(*this, network);
}

Own<ConnectionReceiver> NoiseContext::wrapPort(Own<ConnectionReceiver> port) {
  return heap<NoiseConnectionReceiver>(*this, mv(port));
}

}
