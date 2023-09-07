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

class OutgoingMessageImpl;

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
        friend class OutgoingMessageImpl;

        class ErrorHandlerImpl: public kj::TaskSet::ErrorHandler {
          public:
            void taskFailed(kj::Exception&& exception) override {
              kj::throwFatalException(kj::mv(exception));
            }
        };

        kj::Own<capnp::AsyncIoMessageStream> msgStream;
        kj::Promise<void> previousWrite;
    };

    NoiseVatNetwork(kj::Maybe<kj::Own<kj::NetworkAddress>> bindAddressM);
    NoiseVatNetwork(kj::Own<kj::AsyncIoStream> stream);

    ~NoiseVatNetwork() noexcept(false);
    KJ_DISALLOW_COPY_AND_MOVE(NoiseVatNetwork);

    kj::Maybe<kj::Own<NoiseVatNetworkBase::Connection>> connect(rpc::noise::VatId::Reader hostId) override;
    kj::Promise<kj::Own<NoiseVatNetworkBase::Connection>> accept() override;

  private:
    kj::Maybe<kj::Own<kj::NetworkAddress>> bindAddressM;
    kj::Maybe<kj::Own<kj::ConnectionReceiver>> receiverM;
    kj::Maybe<kj::Own<kj::AsyncIoStream>> streamM;
    kj::Own<kj::PromiseFulfiller<kj::Own<NoiseVatNetworkBase::Connection>>> acceptFulfiller;
};

} // namespace capnp

CAPNP_END_HEADER
