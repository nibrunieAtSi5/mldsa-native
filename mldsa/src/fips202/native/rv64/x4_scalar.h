/*
 * Copyright (c) The mlkem-native project authors
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

#ifndef MLD_FIPS202_NATIVE_RV64_X4_SCALAR_H
#define MLD_FIPS202_NATIVE_RV64_X4_SCALAR_H

/* Part of backend API */
#define MLD_USE_FIPS202_X4_NATIVE

#if !defined(__ASSEMBLER__)
#include "../api.h"
#include "src/KeccakP-1600-rv64.h"

#define MLD_KECCAK_LANES 25

#include "src/KeccakP-1600-rv64-x4-vector.h"

/* Check if RVV (RISC-V Vector Extension) is available */
#if  defined(__riscv_vector)

static MLD_INLINE int mld_keccak_f1600_x4_native(uint64_t *state)
{
  /* Use RVV vectorized implementation */
  KeccakP1600_StatePermute_x4_vector_wrapper(state);
  return MLD_NATIVE_FUNC_SUCCESS;
}

#else /* !__riscv_vector */

/* Fallback scalar implementation: call x1 four times */
static MLD_INLINE int mld_keccak_f1600_x4_native(uint64_t *state)
{
  /* Dummy scalar implementation: just call x1 four times */
  KeccakP1600_StatePermute(state + MLD_KECCAK_LANES * 0);
  KeccakP1600_StatePermute(state + MLD_KECCAK_LANES * 1);
  KeccakP1600_StatePermute(state + MLD_KECCAK_LANES * 2);
  KeccakP1600_StatePermute(state + MLD_KECCAK_LANES * 3);
  return MLD_NATIVE_FUNC_SUCCESS;
}

#endif /* __riscv_vector */

#endif /* !__ASSEMBLER__ */

#endif /* !MLD_FIPS202_NATIVE_RV64_X4_SCALAR_H */

