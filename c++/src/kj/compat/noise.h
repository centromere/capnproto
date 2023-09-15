#pragma once

#include <kj/async-io.h>
#include <kj/debug.h>
#include <kj/encoding.h>

KJ_BEGIN_HEADER

namespace kj {

template <uint8_t S>
class FixedBase64Bytes: public FixedArray<byte, S> {
  public:
    FixedBase64Bytes() {
      std::memset(this->begin(), 0, this->size());
    }

    FixedBase64Bytes(const StringPtr data) {
      auto decoded = decodeBase64(data);
      KJ_REQUIRE(decoded.size() == S, "base64-decoded data is of invalid length");
      std::memcpy(this->begin(), decoded.begin(), S);
    }

    const StringPtr asBase64() const { return encodeBase64(*this); }
};

class X25519: public FixedBase64Bytes<32> {
  public:
    X25519() : FixedBase64Bytes<32>() {}
    X25519(const StringPtr data) : FixedBase64Bytes<32>(data) {}

    static int algorithmId();
};

template <typename DH>
class PublicKey {
  public:
    PublicKey(const StringPtr publicData) : publicData(DH(publicData)) {}
    const DH& getPublicData() const { return this->publicData; }

  protected:
    PublicKey() {}

    DH publicData;
};

template <typename DH>
class SecretKey: public PublicKey<DH> {
  public:
    SecretKey(const StringPtr secretData);

  private:
    DH secretData;
};

class NoisePeerIdentity: public PeerIdentity {
  public:
    static Own<NoisePeerIdentity> newInstance(const StringPtr identityStr);
};

class NoiseContext: public SecureNetworkWrapper {
  public:
    NoiseContext(bool initiator, const StringPtr protocol, Maybe<Own<const SecretKey<X25519>>> localIdentityM = nullptr);

    Promise<Own<AsyncIoStream>> wrapServer(Own<AsyncIoStream> stream) override;
    Promise<Own<AsyncIoStream>> wrapClient(Own<AsyncIoStream> stream, StringPtr expectedServerHostname) override;

    Promise<AuthenticatedStream> wrapServer(AuthenticatedStream stream) {}
    Promise<AuthenticatedStream> wrapClient(AuthenticatedStream stream, StringPtr expectedServerHostname) {}

    Own<ConnectionReceiver> wrapPort(Own<ConnectionReceiver> port) override;

    Own<NetworkAddress> wrapAddress(Own<NetworkAddress> address, StringPtr expectedServerHostname) {}
    Own<NetworkAddress> wrapAddress(Own<NetworkAddress> address, const Maybe<const NoisePeerIdentity&> expectedPeerIdentityM = nullptr);

    Own<Network> wrapNetwork(Network& network) override;

  private:
    friend class NoiseHandshake;

    bool initiator;
    Own<void> protocolId; // actually type NoiseProtocolId, but I do not wish to #include the noise-c headers here.
    const Maybe<Own<const SecretKey<X25519>>> localIdentityM;
};

} // namespace kj

KJ_END_HEADER
