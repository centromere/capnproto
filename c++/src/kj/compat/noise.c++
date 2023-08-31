#include <iostream>

#include "noise.h"

namespace kj {

NoiseContext::NoiseContext() {
  int err;

  err = noise_handshakestate_new_by_name(&this->hstate, "Noise_NN_25519_ChaChaPoly_BLAKE2s", NOISE_ROLE_INITIATOR);
  if (err != NOISE_ERROR_NONE) {
    noise_perror("foo", err);
  }

  err = noise_handshakestate_start(this->hstate);
  if (err != NOISE_ERROR_NONE) {
    noise_perror("bar", err);
  }

  uint8_t m[2048];
  NoiseBuffer mbuf;
  noise_buffer_set_output(mbuf, m, sizeof(m));
  noise_handshakestate_write_message(this->hstate, &mbuf, nullptr);

  for(int i = 0; i < mbuf.size; i++) {
    std::cout << m[i];
  }
  std::cout.flush();
}

NoiseContext::~NoiseContext() {
  if (this->hstate) {
    noise_handshakestate_free(this->hstate);
  }
}

}
