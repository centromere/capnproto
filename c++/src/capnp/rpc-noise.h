#pragma once

#include <kj/async.h>
#include <kj/async-io.h>

#include "rpc.h"
#include "serialize-async.h"
#include <capnp/rpc-noise.capnp.h>

CAPNP_BEGIN_HEADER

namespace capnp {

typedef VatNetwork<rpc::noise::VatId, rpc::noise::ProvisionId,
    rpc::noise::RecipientId, rpc::noise::ThirdPartyCapId, rpc::noise::JoinResult>
    NoiseVatNetworkBase;

class NoiseVatNetwork: public NoiseVatNetworkBase {
  class IncomingMessageImpl;

  public:
    class Connection : public NoiseVatNetworkBase::Connection {
      public:
        Connection(kj::Own<kj::AsyncIoStream> stream);

        kj::Own<OutgoingRpcMessage> newOutgoingMessage(uint firstSegmentWordSize) override;
        kj::Promise<kj::Maybe<kj::Own<IncomingRpcMessage>>> receiveIncomingMessage() override;
        kj::Promise<void> shutdown() override;

        rpc::noise::VatId::Reader getPeerVatId() override;

      private:
        kj::Own<capnp::AsyncIoMessageStream> msgStream;
    };

    NoiseVatNetwork(kj::Maybe<kj::Own<kj::NetworkAddress>> bindAddressM);

    ~NoiseVatNetwork() noexcept(false);
    KJ_DISALLOW_COPY_AND_MOVE(NoiseVatNetwork);

    kj::Maybe<kj::Own<NoiseVatNetworkBase::Connection>> connect(rpc::noise::VatId::Reader hostId) override;
    kj::Promise<kj::Own<NoiseVatNetworkBase::Connection>> accept() override;

  private:
    kj::Maybe<kj::Own<kj::NetworkAddress>> bindAddressM;
    kj::Maybe<kj::Own<kj::ConnectionReceiver>> receiverM;
};

} // namespace capnp

CAPNP_END_HEADER
