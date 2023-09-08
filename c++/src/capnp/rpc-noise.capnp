@0xe7174c4e92d15add;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("capnp::rpc::noise");

struct Bytes16 {
  a @0 :UInt64;
  b @1 :UInt64;
}

struct Bytes32 {
  a @0 :UInt64;
  b @1 :UInt64;
  c @2 :UInt64;
  d @3 :UInt64;
}

struct Bytes56 {
  a @0 :UInt64;
  b @1 :UInt64;
  c @2 :UInt64;
  d @3 :UInt64;
  e @4 :UInt64;
  f @5 :UInt64;
  g @6 :UInt64;
}

struct PublicKey {
  union {
    x25519 :group {
      bytes @0 :Bytes32;
    }

    x448 :group {
      bytes @1 :Bytes56;
    }
  }
}

struct VatId {
  publicKey @0 :PublicKey;
}

using Nonce = UInt64;

struct ProvisionId {
  providerVatId @0 :VatId;
  nonce @1 :Nonce;
}

struct RecipientId {
  recipientVatId @0 :VatId;
  nonce @1 :Nonce;
}

struct VatAddress {
  union {
    ipv6 :group {
      bytes @0 :Bytes16;
    }

    ipv4 :group {
      bytes @1 :UInt32;
    }
  }
}

struct ThirdPartyCapId {
  address @0 :VatAddress;
  vatId @1 :VatId;
}

struct JoinResult {}
