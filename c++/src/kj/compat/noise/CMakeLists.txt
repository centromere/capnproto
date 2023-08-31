cmake_minimum_required(VERSION 3.23)
project("noise-c" C)

add_library(kj-noiseprotocol)

target_sources(kj-noiseprotocol PRIVATE
  noise-c/src/backend/ref/dh-curve448.c
  noise-c/src/backend/ref/dh-newhope.c
  noise-c/src/backend/ref/cipher-aesgcm.c
  noise-c/src/backend/ref/hash-blake2s.c
  noise-c/src/backend/sodium/cipher-aesgcm.c
  noise-c/src/backend/sodium/cipher-chachapoly.c
  noise-c/src/backend/sodium/dh-curve25519.c
  noise-c/src/backend/sodium/hash-blake2b.c
  noise-c/src/backend/sodium/hash-sha256.c
  noise-c/src/backend/sodium/hash-sha512.c
  noise-c/src/backend/sodium/sign-ed25519.c
  noise-c/src/crypto/aes/rijndael-alg-fst.c
  noise-c/src/crypto/blake2/blake2s.c
  noise-c/src/crypto/curve448/curve448.c
  noise-c/src/crypto/ghash/ghash.c
  noise-c/src/crypto/goldilocks/src/p448/arch_x86_64/p448.c
  noise-c/src/crypto/newhope/batcher.c
  noise-c/src/crypto/newhope/error_correction.c
  noise-c/src/crypto/newhope/fips202.c
  noise-c/src/crypto/newhope/newhope.c
  noise-c/src/crypto/newhope/ntt.c
  noise-c/src/crypto/newhope/poly.c
  noise-c/src/crypto/newhope/precomp.c
  noise-c/src/crypto/newhope/reduce.c
  noise-c/src/protocol/cipherstate.c
  noise-c/src/protocol/dhstate.c
  noise-c/src/protocol/errors.c
  noise-c/src/protocol/handshakestate.c
  noise-c/src/protocol/hashstate.c
  noise-c/src/protocol/internal.c
  noise-c/src/protocol/names.c
  noise-c/src/protocol/patterns.c
  noise-c/src/protocol/rand_sodium.c
  noise-c/src/protocol/randstate.c
  noise-c/src/protocol/signstate.c
  noise-c/src/protocol/symmetricstate.c
  noise-c/src/protocol/util.c
)

target_sources(kj-noiseprotocol PRIVATE
  FILE_SET goldilocks
  TYPE HEADERS
  BASE_DIRS noise-c/src/crypto/goldilocks/src/include
  FILES
  noise-c/src/crypto/goldilocks/src/include/field.h
)

target_sources(kj-noiseprotocol PRIVATE
  FILE_SET goldilocks2
  TYPE HEADERS
  BASE_DIRS noise-c/src/crypto/goldilocks/src/p448/arch_x86_64
  FILES
  noise-c/src/crypto/goldilocks/src/p448/arch_x86_64/arch_config.h
)

target_sources(kj-noiseprotocol PRIVATE
  FILE_SET goldilocks3
  TYPE HEADERS
  BASE_DIRS noise-c/src/crypto/goldilocks/src/p448
  FILES
  noise-c/src/crypto/goldilocks/src/p448/f_field.h
)

target_sources(kj-noiseprotocol PRIVATE
  FILE_SET crypto
  TYPE HEADERS
  BASE_DIRS noise-c/src
  FILES
  noise-c/src/crypto/chacha/chacha.h
)

target_sources(kj-noiseprotocol PRIVATE
  FILE_SET internal
  TYPE HEADERS
  BASE_DIRS noise-c/src/protocol
  FILES
  noise-c/src/protocol/internal.h
)

target_sources(kj-noiseprotocol PUBLIC
  FILE_SET main
  TYPE HEADERS
  BASE_DIRS noise-c/include
  FILES
  noise-c/include/noise/protocol.h
  noise-c/include/noise/protocol/buffer.h
  noise-c/include/noise/protocol/cipherstate.h
  noise-c/include/noise/protocol/constants.h
  noise-c/include/noise/protocol/dhstate.h
  noise-c/include/noise/protocol/errors.h
  noise-c/include/noise/protocol/handshakestate.h
  noise-c/include/noise/protocol/hashstate.h
  noise-c/include/noise/protocol/names.h
  noise-c/include/noise/protocol/randstate.h
  noise-c/include/noise/protocol/signstate.h
  noise-c/include/noise/protocol/symmetricstate.h
  noise-c/include/noise/protocol/util.h
)

target_compile_definitions(kj-noiseprotocol PRIVATE USE_LIBSODIUM)

target_include_directories(kj-noiseprotocol
  PRIVATE include ${SODIUM_INCLUDE_DIRS}
)

target_link_directories(kj-noiseprotocol PUBLIC ${SODIUM_LIBRARY_DIRS})
target_link_libraries(kj-noiseprotocol PUBLIC sodium)
