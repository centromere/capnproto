#pragma once

#include <kj/async-io.h>

#include <noise/protocol.h>

KJ_BEGIN_HEADER

namespace kj {

class NoiseContext: public kj::SecureNetworkWrapper {
  public:
    NoiseContext();

    kj::Promise<kj::Own<kj::AsyncIoStream>> wrapServer(kj::Own<kj::AsyncIoStream> stream) {}

    kj::Promise<kj::Own<kj::AsyncIoStream>> wrapClient(kj::Own<kj::AsyncIoStream> stream, kj::StringPtr expectedServerHostname) {}

    kj::Promise<kj::AuthenticatedStream> wrapServer(kj::AuthenticatedStream stream) {}
    kj::Promise<kj::AuthenticatedStream> wrapClient(kj::AuthenticatedStream stream, kj::StringPtr expectedServerHostname) {}

    kj::Own<kj::ConnectionReceiver> wrapPort(kj::Own<kj::ConnectionReceiver> port) {}

    kj::Own<kj::NetworkAddress> wrapAddress(kj::Own<kj::NetworkAddress> address, kj::StringPtr expectedServerHostname) {}

    kj::Own<kj::Network> wrapNetwork(kj::Network& network) {}

  private:
    NoiseHandshakeState* hstate;
};

} // namespace kj

KJ_END_HEADER
