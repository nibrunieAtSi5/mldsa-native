/*
 * Copyright (c) The mlkem-native project authors
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

#ifndef KECCAKP_1600_RV64_X4_VECTOR_H
#define KECCAKP_1600_RV64_X4_VECTOR_H

#include <stdint.h>

/* RVV-based x4 vectorized Keccak permutation */
void KeccakP1600_StatePermute_x4_vector(uint64_t *state);
void KeccakP1600_StatePermute_x4_vector_wrapper(uint64_t *state);

#endif /* KECCAKP_1600_RV64_X4_VECTOR_H */
