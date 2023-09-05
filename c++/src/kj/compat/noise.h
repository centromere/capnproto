#pragma once

#include <noise/protocol.h>

#include <kj/async-io.h>
#include <kj/debug.h>
#include <kj/encoding.h>

KJ_BEGIN_HEADER

namespace kj {

template <uint8_t S>
class FixedBase64Bytes : public kj::FixedArray<byte, S> {
  public:
    FixedBase64Bytes() {
      std::memset(this->begin(), 0, this->size());
    }

    FixedBase64Bytes(const kj::StringPtr data) {
      auto decoded = decodeBase64(data);
      KJ_REQUIRE(decoded.size() == S, "base64-decoded data is of invalid length");
      std::memcpy(this->begin(), decoded.begin(), S);
    }

    const kj::StringPtr asBase64() const { return encodeBase64(*this); }
};

class Curve25519: public FixedBase64Bytes<32> {
  public:
    Curve25519() {}

    Curve25519(const kj::StringPtr data) : FixedBase64Bytes(data) {}

  static int algorithmId() {
    return NOISE_DH_CURVE25519;
  }
};

template <typename DH>
class PublicKey {
  public:
    PublicKey(const DH& publicData) : publicData(publicData) {}

    PublicKey(const kj::StringPtr publicBase64) : PublicKey(DH(publicBase64)) {}

    const DH& getPublicData() const { return this->publicData; }

  protected:
    PublicKey() {}

    DH publicData;
};

template <typename DH>
class SecretKey: public PublicKey<DH> {
  public:
    SecretKey(const DH& secretData) : secretData(secretData), PublicKey<DH>() {
      NoiseDHState* state;
      noise_dhstate_new_by_id(&state, DH::algorithmId());

      noise_dhstate_set_keypair_private(state, this->secretData.begin(), this->secretData.size());

      noise_dhstate_get_public_key(state, this->publicData.begin(), this->publicData.size());
    }

    SecretKey(const kj::StringPtr secretBase64) : SecretKey(DH(secretBase64)) {}

    const DH& getSecretData() const { return this->secretData; }

  private:
    DH secretData;
};

class NoisePeerIdentity: public PeerIdentity {
  public:
    static kj::Own<NoisePeerIdentity> newInstance(const kj::StringPtr identityStr);
};

class NoiseContext: public kj::SecureNetworkWrapper {
  public:
    NoiseContext(bool initiator, const kj::StringPtr protocol, kj::Maybe<kj::Own<const SecretKey<Curve25519>>> localIdentityM = nullptr);

    kj::Promise<kj::Own<kj::AsyncIoStream>> wrapServer(kj::Own<kj::AsyncIoStream> stream) override;

    kj::Promise<kj::Own<kj::AsyncIoStream>> wrapClient(kj::Own<kj::AsyncIoStream> stream, kj::StringPtr expectedServerHostname) override;

    kj::Promise<kj::AuthenticatedStream> wrapServer(kj::AuthenticatedStream stream) {}
    kj::Promise<kj::AuthenticatedStream> wrapClient(kj::AuthenticatedStream stream, kj::StringPtr expectedServerHostname) {}

    kj::Own<kj::ConnectionReceiver> wrapPort(kj::Own<kj::ConnectionReceiver> port) override;

    kj::Own<kj::NetworkAddress> wrapAddress(kj::Own<kj::NetworkAddress> address, kj::StringPtr expectedServerHostname) {}

    kj::Own<kj::NetworkAddress> wrapAddress(kj::Own<kj::NetworkAddress> address, const kj::Maybe<const kj::NoisePeerIdentity&> expectedPeerIdentityM = nullptr);

    kj::Own<kj::Network> wrapNetwork(kj::Network& network) override;

  private:
    friend class NoiseHandshake;

    bool initiator;
    const kj::Maybe<kj::Own<const SecretKey<Curve25519>>> localIdentityM;
    NoiseProtocolId protocolId;
};

} // namespace kj

KJ_END_HEADER
