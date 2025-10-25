[//]: # (SPDX-License-Identifier: CC-BY-4.0)

# Bring your own FIPS-202

This directory contains a minimal example for how to use mldsa-native as a code package, with a custom FIPS-202
implementation. We use tiny_sha3[^tiny_sha3] as an example.

## Components

An application using mldsa-native with a custom FIPS-202 implementation needs the following:

1. Arithmetic part of the mldsa-native source tree: [`mldsa/`](../../mldsa)
2. A secure pseudo random number generator, implementing [`randombytes.h`](../../mldsa/randombytes.h).
3. A custom FIPS-202 with `fips202.h` and `fips202x4.h` headers compatible with
   [`mldsa/fips202/fips202.h`](../../mldsa/fips202/fips202.h) and [`mldsa/fips202/fips202x4.h`](../../mldsa/fips202/fips202x4.h).
4. The application source code

**WARNING:** The `randombytes()` implementation used here is for TESTING ONLY. You MUST NOT use this implementation
outside of testing.

## Usage

Build this example with `make build`, run with `make run`.

## Custom FIPS-202 Implementation

This example uses tiny_sha3 as the underlying Keccak/SHA3 implementation. The wrapper headers in `custom_fips202/`
adapt the tiny_sha3 API to match the API expected by mldsa-native.

Note that the `fips202x4.h` implementation provided here is a simple serial implementation that does not provide
any performance benefits from parallelization. For production use, consider using an optimized parallel implementation.

## Verification

This example uses the same test vectors as the basic example (via a symlink to `expected_signatures.h`) and verifies
that the custom FIPS-202 implementation produces identical results to the default implementation. This ensures that
the wrapper is correctly implementing the required API.

<!--- bibliography --->
[^tiny_sha3]: Markku-Juhani O. Saarinen: tiny_sha3, [https://github.com/mjosaarinen/tiny_sha3](https://github.com/mjosaarinen/tiny_sha3)
