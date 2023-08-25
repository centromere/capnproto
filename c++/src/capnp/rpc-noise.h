#pragma once

#include "rpc.h"
#include <capnp/rpc-noise.capnp.h>

CAPNP_BEGIN_HEADER

namespace capnp {

typedef VatNetwork<rpc::noise::VatId, rpc::noise::ProvisionId,
    rpc::noise::RecipientId, rpc::noise::ThirdPartyCapId, rpc::noise::JoinResult>
    NoiseVatNetworkBase;

class NoiseVatNetwork: public NoiseVatNetworkBase {
  public:
    NoiseVatNetwork();

    ~NoiseVatNetwork() noexcept(false);
    KJ_DISALLOW_COPY_AND_MOVE(NoiseVatNetwork);
};

} // namespace capnp

CAPNP_END_HEADER
