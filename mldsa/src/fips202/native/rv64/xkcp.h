/*
 * Copyright (c) The mlkem-native project authors
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

#ifndef MLD_FIPS202_NATIVE_RV64_XKCP_H
#define MLD_FIPS202_NATIVE_RV64_XKCP_H

#include "../../../common.h"

#define MLD_FIPS202_RV64_XKCP

#if !defined(__ASSEMBLER__)
#include <stdint.h>
#include "../api.h"

#define KECCAK_SYMBOL
void KeccakP1600_StatePermute(uint64_t *state);

#define MLD_USE_FIPS202_X1_NATIVE
static MLD_INLINE int mld_keccak_f1600_x1_native(uint64_t *state)
{
  KeccakP1600_StatePermute(state);
  return MLD_NATIVE_FUNC_SUCCESS;
}

/* Include x4 scalar implementation */
#include "x4_scalar.h"

#endif /* !__ASSEMBLER__ */

#endif /* !MLD_FIPS202_NATIVE_RV64_XKCP_H */

