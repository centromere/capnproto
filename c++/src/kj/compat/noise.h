#pragma once

#include <noise/protocol.h>

#include <kj/async-io.h>

KJ_BEGIN_HEADER

namespace kj {

typedef kj::FixedArray<byte, 32> Curve25519Key;

class NoisePeerIdentity: public PeerIdentity {
  public:
    static kj::Own<NoisePeerIdentity> newInstance(const Curve25519Key& publicKey);
    static kj::Own<NoisePeerIdentity> newInstance(const kj::StringPtr publicKey);
};

class NoiseContext: public kj::SecureNetworkWrapper {
  public:
    NoiseContext(kj::Maybe<kj::StringPtr> localStaticKeyM);

    kj::Promise<kj::Own<kj::AsyncIoStream>> wrapServer(kj::Own<kj::AsyncIoStream> stream) override;

    kj::Promise<kj::Own<kj::AsyncIoStream>> wrapClient(kj::Own<kj::AsyncIoStream> stream, kj::StringPtr expectedServerHostname) {}

    kj::Promise<kj::AuthenticatedStream> wrapServer(kj::AuthenticatedStream stream) {}
    kj::Promise<kj::AuthenticatedStream> wrapClient(kj::AuthenticatedStream stream, kj::StringPtr expectedServerHostname) {}

    kj::Own<kj::ConnectionReceiver> wrapPort(kj::Own<kj::ConnectionReceiver> port) override;

    kj::Own<kj::NetworkAddress> wrapAddress(kj::Own<kj::NetworkAddress> address, kj::StringPtr expectedServerHostname) override;

    kj::Own<kj::Network> wrapNetwork(kj::Network& network) override;

  private:
    kj::Maybe<Curve25519Key> localStaticKeyM;
};

} // namespace kj

KJ_END_HEADER
