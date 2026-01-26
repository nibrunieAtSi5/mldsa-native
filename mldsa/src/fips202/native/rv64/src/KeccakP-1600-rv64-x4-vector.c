/*
 * Copyright (c) The mlkem-native project authors
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

/* RISC-V Vector Extension (RVV) based x4 Keccak-f[1600] implementation */

#include "../../../../common.h"

#if defined(__riscv_vector)

#include <stdint.h>
#include <riscv_vector.h>

#define NROUNDS 24
#define MLD_KECCAK_LANES 25

static const uint64_t RC[24] = {
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x0000000080008008
};

/** RISC-V vector rotate right (if Zvkb is not implemented, can be emulated with RVV 1.0 operations) */
static inline vuint64m1_t __riscv_vror_vx_u64m1(vuint64m1_t v, uint64_t shamt, size_t vl)
{
    return __riscv_vror_vv_u64m1(__riscv_vsrl_vx_u64m1(v, shamt, vl), __riscv_vsll_vx_u64m1(v, 64 - shamt, vl), vl);
}

static inline vuint64m1_t __riscv_vror_vv_u64m1(vuint64m1_t v, vuint64m1_t shamt, size_t vl)
{
    return __riscv_vror_vv_u64m1(__riscv_vsrl_vv_u64m1(v, shamt, vl), __riscv_vsll_vv_u64m1(v, 64 - shamt, vl), vl);
}
/* RVV-based x4 vectorized Keccak permutation
 * Processes 4 Keccak states in parallel using RISC-V Vector extension
 * state: pointer to array of 4*25 uint64_t elements (100 elements total)
 *        organized as state[0..24] for first state, state[25..49] for second, etc.
 *        States are CONTIGUOUS, not interleaved.
 */
void KeccakP1600_StatePermute_x4_vector(uint64_t *state)
{
    size_t vl = __riscv_vsetvl_e64m1(4); // Process 4 elements at a time
    const ptrdiff_t stride = MLD_KECCAK_LANES * sizeof(uint64_t); // 25 * 8 = 200 bytes
    
    for (unsigned int round = 0; round < NROUNDS; round++)
    {
        // Theta step: Compute column parities C[x] = A[x,0] ^ A[x,1] ^ A[x,2] ^ A[x,3] ^ A[x,4]
        vuint64m1_t C_0, C_1, C_2, C_3, C_4;
        vuint64m1_t lane_tmp;
        
        // C_0 = A[0,0] ^ A[0,1] ^ A[0,2] ^ A[0,3] ^ A[0,4]
        C_0 = __riscv_vlse64_v_u64m1(&state[0], stride, vl);
        lane_tmp = __riscv_vlse64_v_u64m1(&state[1], stride, vl);
        C_0 = __riscv_vxor_vv_u64m1(C_0, lane_tmp, vl);
        lane_tmp = __riscv_vlse64_v_u64m1(&state[2], stride, vl);
        C_0 = __riscv_vxor_vv_u64m1(C_0, lane_tmp, vl);
        lane_tmp = __riscv_vlse64_v_u64m1(&state[3], stride, vl);
        C_0 = __riscv_vxor_vv_u64m1(C_0, lane_tmp, vl);
        lane_tmp = __riscv_vlse64_v_u64m1(&state[4], stride, vl);
        C_0 = __riscv_vxor_vv_u64m1(C_0, lane_tmp, vl);
        
        // C_1 = A[1,0] ^ A[1,1] ^ A[1,2] ^ A[1,3] ^ A[1,4]
        C_1 = __riscv_vlse64_v_u64m1(&state[5], stride, vl);
        lane_tmp = __riscv_vlse64_v_u64m1(&state[6], stride, vl);
        C_1 = __riscv_vxor_vv_u64m1(C_1, lane_tmp, vl);
        lane_tmp = __riscv_vlse64_v_u64m1(&state[7], stride, vl);
        C_1 = __riscv_vxor_vv_u64m1(C_1, lane_tmp, vl);
        lane_tmp = __riscv_vlse64_v_u64m1(&state[8], stride, vl);
        C_1 = __riscv_vxor_vv_u64m1(C_1, lane_tmp, vl);
        lane_tmp = __riscv_vlse64_v_u64m1(&state[9], stride, vl);
        C_1 = __riscv_vxor_vv_u64m1(C_1, lane_tmp, vl);
        
        // C_2 = A[2,0] ^ A[2,1] ^ A[2,2] ^ A[2,3] ^ A[2,4]
        C_2 = __riscv_vlse64_v_u64m1(&state[10], stride, vl);
        lane_tmp = __riscv_vlse64_v_u64m1(&state[11], stride, vl);
        C_2 = __riscv_vxor_vv_u64m1(C_2, lane_tmp, vl);
        lane_tmp = __riscv_vlse64_v_u64m1(&state[12], stride, vl);
        C_2 = __riscv_vxor_vv_u64m1(C_2, lane_tmp, vl);
        lane_tmp = __riscv_vlse64_v_u64m1(&state[13], stride, vl);
        C_2 = __riscv_vxor_vv_u64m1(C_2, lane_tmp, vl);
        lane_tmp = __riscv_vlse64_v_u64m1(&state[14], stride, vl);
        C_2 = __riscv_vxor_vv_u64m1(C_2, lane_tmp, vl);
        
        // C_3 = A[3,0] ^ A[3,1] ^ A[3,2] ^ A[3,3] ^ A[3,4]
        C_3 = __riscv_vlse64_v_u64m1(&state[15], stride, vl);
        lane_tmp = __riscv_vlse64_v_u64m1(&state[16], stride, vl);
        C_3 = __riscv_vxor_vv_u64m1(C_3, lane_tmp, vl);
        lane_tmp = __riscv_vlse64_v_u64m1(&state[17], stride, vl);
        C_3 = __riscv_vxor_vv_u64m1(C_3, lane_tmp, vl);
        lane_tmp = __riscv_vlse64_v_u64m1(&state[18], stride, vl);
        C_3 = __riscv_vxor_vv_u64m1(C_3, lane_tmp, vl);
        lane_tmp = __riscv_vlse64_v_u64m1(&state[19], stride, vl);
        C_3 = __riscv_vxor_vv_u64m1(C_3, lane_tmp, vl);
        
        // C_4 = A[4,0] ^ A[4,1] ^ A[4,2] ^ A[4,3] ^ A[4,4]
        C_4 = __riscv_vlse64_v_u64m1(&state[20], stride, vl);
        lane_tmp = __riscv_vlse64_v_u64m1(&state[21], stride, vl);
        C_4 = __riscv_vxor_vv_u64m1(C_4, lane_tmp, vl);
        lane_tmp = __riscv_vlse64_v_u64m1(&state[22], stride, vl);
        C_4 = __riscv_vxor_vv_u64m1(C_4, lane_tmp, vl);
        lane_tmp = __riscv_vlse64_v_u64m1(&state[23], stride, vl);
        C_4 = __riscv_vxor_vv_u64m1(C_4, lane_tmp, vl);
        lane_tmp = __riscv_vlse64_v_u64m1(&state[24], stride, vl);
        C_4 = __riscv_vxor_vv_u64m1(C_4, lane_tmp, vl);
        
        // Compute D values: D[x] = C[x-1] ^ ROL(C[x+1], 1)
        vuint64m1_t D_0, D_1, D_2, D_3, D_4;
        vuint64m1_t rotated;
        
        rotated = __riscv_vror_vx_u64m1(C_1, 63, vl);
        D_0 = __riscv_vxor_vv_u64m1(C_4, rotated, vl);
        
        rotated = __riscv_vror_vx_u64m1(C_2, 63, vl);
        D_1 = __riscv_vxor_vv_u64m1(C_0, rotated, vl);
        
        rotated = __riscv_vror_vx_u64m1(C_3, 63, vl);
        D_2 = __riscv_vxor_vv_u64m1(C_1, rotated, vl);
        
        rotated = __riscv_vror_vx_u64m1(C_4, 63, vl);
        D_3 = __riscv_vxor_vv_u64m1(C_2, rotated, vl);
        
        rotated = __riscv_vror_vx_u64m1(C_0, 63, vl);
        D_4 = __riscv_vxor_vv_u64m1(C_3, rotated, vl);
        
        // Apply theta and load state into registers: A[x,y] ^= D[x]
        vuint64m1_t A_0_0, A_0_1, A_0_2, A_0_3, A_0_4;
        vuint64m1_t A_1_0, A_1_1, A_1_2, A_1_3, A_1_4;
        vuint64m1_t A_2_0, A_2_1, A_2_2, A_2_3, A_2_4;
        vuint64m1_t A_3_0, A_3_1, A_3_2, A_3_3, A_3_4;
        vuint64m1_t A_4_0, A_4_1, A_4_2, A_4_3, A_4_4;
        
        A_0_0 = __riscv_vlse64_v_u64m1(&state[0], stride, vl);
        A_0_0 = __riscv_vxor_vv_u64m1(A_0_0, D_0, vl);
        A_0_1 = __riscv_vlse64_v_u64m1(&state[1], stride, vl);
        A_0_1 = __riscv_vxor_vv_u64m1(A_0_1, D_0, vl);
        A_0_2 = __riscv_vlse64_v_u64m1(&state[2], stride, vl);
        A_0_2 = __riscv_vxor_vv_u64m1(A_0_2, D_0, vl);
        A_0_3 = __riscv_vlse64_v_u64m1(&state[3], stride, vl);
        A_0_3 = __riscv_vxor_vv_u64m1(A_0_3, D_0, vl);
        A_0_4 = __riscv_vlse64_v_u64m1(&state[4], stride, vl);
        A_0_4 = __riscv_vxor_vv_u64m1(A_0_4, D_0, vl);
        
        A_1_0 = __riscv_vlse64_v_u64m1(&state[5], stride, vl);
        A_1_0 = __riscv_vxor_vv_u64m1(A_1_0, D_1, vl);
        A_1_1 = __riscv_vlse64_v_u64m1(&state[6], stride, vl);
        A_1_1 = __riscv_vxor_vv_u64m1(A_1_1, D_1, vl);
        A_1_2 = __riscv_vlse64_v_u64m1(&state[7], stride, vl);
        A_1_2 = __riscv_vxor_vv_u64m1(A_1_2, D_1, vl);
        A_1_3 = __riscv_vlse64_v_u64m1(&state[8], stride, vl);
        A_1_3 = __riscv_vxor_vv_u64m1(A_1_3, D_1, vl);
        A_1_4 = __riscv_vlse64_v_u64m1(&state[9], stride, vl);
        A_1_4 = __riscv_vxor_vv_u64m1(A_1_4, D_1, vl);
        
        A_2_0 = __riscv_vlse64_v_u64m1(&state[10], stride, vl);
        A_2_0 = __riscv_vxor_vv_u64m1(A_2_0, D_2, vl);
        A_2_1 = __riscv_vlse64_v_u64m1(&state[11], stride, vl);
        A_2_1 = __riscv_vxor_vv_u64m1(A_2_1, D_2, vl);
        A_2_2 = __riscv_vlse64_v_u64m1(&state[12], stride, vl);
        A_2_2 = __riscv_vxor_vv_u64m1(A_2_2, D_2, vl);
        A_2_3 = __riscv_vlse64_v_u64m1(&state[13], stride, vl);
        A_2_3 = __riscv_vxor_vv_u64m1(A_2_3, D_2, vl);
        A_2_4 = __riscv_vlse64_v_u64m1(&state[14], stride, vl);
        A_2_4 = __riscv_vxor_vv_u64m1(A_2_4, D_2, vl);
        
        A_3_0 = __riscv_vlse64_v_u64m1(&state[15], stride, vl);
        A_3_0 = __riscv_vxor_vv_u64m1(A_3_0, D_3, vl);
        A_3_1 = __riscv_vlse64_v_u64m1(&state[16], stride, vl);
        A_3_1 = __riscv_vxor_vv_u64m1(A_3_1, D_3, vl);
        A_3_2 = __riscv_vlse64_v_u64m1(&state[17], stride, vl);
        A_3_2 = __riscv_vxor_vv_u64m1(A_3_2, D_3, vl);
        A_3_3 = __riscv_vlse64_v_u64m1(&state[18], stride, vl);
        A_3_3 = __riscv_vxor_vv_u64m1(A_3_3, D_3, vl);
        A_3_4 = __riscv_vlse64_v_u64m1(&state[19], stride, vl);
        A_3_4 = __riscv_vxor_vv_u64m1(A_3_4, D_3, vl);
        
        A_4_0 = __riscv_vlse64_v_u64m1(&state[20], stride, vl);
        A_4_0 = __riscv_vxor_vv_u64m1(A_4_0, D_4, vl);
        A_4_1 = __riscv_vlse64_v_u64m1(&state[21], stride, vl);
        A_4_1 = __riscv_vxor_vv_u64m1(A_4_1, D_4, vl);
        A_4_2 = __riscv_vlse64_v_u64m1(&state[22], stride, vl);
        A_4_2 = __riscv_vxor_vv_u64m1(A_4_2, D_4, vl);
        A_4_3 = __riscv_vlse64_v_u64m1(&state[23], stride, vl);
        A_4_3 = __riscv_vxor_vv_u64m1(A_4_3, D_4, vl);
        A_4_4 = __riscv_vlse64_v_u64m1(&state[24], stride, vl);
        A_4_4 = __riscv_vxor_vv_u64m1(A_4_4, D_4, vl);
        
        // Rho and Pi steps combined: B[y, 2x+3y] = ROL(A[x,y], r[x,y])
        vuint64m1_t B_0_0, B_0_1, B_0_2, B_0_3, B_0_4;
        vuint64m1_t B_1_0, B_1_1, B_1_2, B_1_3, B_1_4;
        vuint64m1_t B_2_0, B_2_1, B_2_2, B_2_3, B_2_4;
        vuint64m1_t B_3_0, B_3_1, B_3_2, B_3_3, B_3_4;
        vuint64m1_t B_4_0, B_4_1, B_4_2, B_4_3, B_4_4;
        
        // Unrolled rho/pi permutation
        B_0_0 = A_0_0;  // (0,0) -> (0,0), offset 0
        B_1_0 = __riscv_vror_vx_u64m1(A_0_1, 63, vl);  // (0,1) -> (1,0), offset 1
        B_2_0 = __riscv_vror_vx_u64m1(A_0_2, 2, vl);  // (0,2) -> (2,0), offset 62
        B_3_0 = __riscv_vror_vx_u64m1(A_0_3, 36, vl);  // (0,3) -> (3,0), offset 28
        B_4_0 = __riscv_vror_vx_u64m1(A_0_4, 37, vl);  // (0,4) -> (4,0), offset 27
        
        B_0_2 = __riscv_vror_vx_u64m1(A_1_0, 28, vl);  // (1,0) -> (0,2), offset 36
        B_1_1 = __riscv_vror_vx_u64m1(A_1_1, 20, vl);  // (1,1) -> (1,1), offset 44
        B_2_2 = __riscv_vror_vx_u64m1(A_1_2, 58, vl);  // (1,2) -> (2,2), offset 6
        B_3_3 = __riscv_vror_vx_u64m1(A_1_3, 9, vl);  // (1,3) -> (3,3), offset 55
        B_4_4 = __riscv_vror_vx_u64m1(A_1_4, 44, vl);  // (1,4) -> (4,4), offset 20
        
        B_0_4 = __riscv_vror_vx_u64m1(A_2_0, 61, vl);  // (2,0) -> (0,4), offset 3
        B_1_3 = __riscv_vror_vx_u64m1(A_2_1, 54, vl);  // (2,1) -> (1,3), offset 10
        B_2_1 = __riscv_vror_vx_u64m1(A_2_2, 21, vl);  // (2,2) -> (2,1), offset 43
        B_3_4 = __riscv_vror_vx_u64m1(A_2_3, 39, vl);  // (2,3) -> (3,4), offset 25
        B_4_2 = __riscv_vror_vx_u64m1(A_2_4, 25, vl);  // (2,4) -> (4,2), offset 39
        
        B_0_1 = __riscv_vror_vx_u64m1(A_3_0, 23, vl);  // (3,0) -> (0,1), offset 41
        B_1_2 = __riscv_vror_vx_u64m1(A_3_1, 19, vl);  // (3,1) -> (1,2), offset 45
        B_2_3 = __riscv_vror_vx_u64m1(A_3_2, 49, vl);  // (3,2) -> (2,3), offset 15
        B_3_4 = __riscv_vror_vx_u64m1(A_3_3, 43, vl);  // (3,3) -> (3,4), offset 21
        B_4_0 = __riscv_vror_vx_u64m1(A_3_4, 56, vl);  // (3,4) -> (4,0), offset 8
        
        B_0_3 = __riscv_vror_vx_u64m1(A_4_0, 46, vl);  // (4,0) -> (0,3), offset 18
        B_1_4 = __riscv_vror_vx_u64m1(A_4_1, 62, vl);  // (4,1) -> (1,4), offset 2
        B_2_4 = __riscv_vror_vx_u64m1(A_4_2, 3, vl);  // (4,2) -> (2,4), offset 61
        B_3_1 = __riscv_vror_vx_u64m1(A_4_3, 8, vl);  // (4,3) -> (3,1), offset 56
        B_4_3 = __riscv_vror_vx_u64m1(A_4_4, 50, vl);  // (4,4) -> (4,3), offset 14
        
        // Chi step: A[x,y] = B[x,y] ^ ((~B[x+1,y]) & B[x+2,y])
        vuint64m1_t not_tmp, and_tmp;
        
        not_tmp = __riscv_vnot_v_u64m1(B_1_0, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_2_0, vl);
        A_0_0 = __riscv_vxor_vv_u64m1(B_0_0, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_2_0, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_3_0, vl);
        A_1_0 = __riscv_vxor_vv_u64m1(B_1_0, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_3_0, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_4_0, vl);
        A_2_0 = __riscv_vxor_vv_u64m1(B_2_0, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_4_0, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_0_0, vl);
        A_3_0 = __riscv_vxor_vv_u64m1(B_3_0, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_0_0, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_1_0, vl);
        A_4_0 = __riscv_vxor_vv_u64m1(B_4_0, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_1_1, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_2_1, vl);
        A_0_1 = __riscv_vxor_vv_u64m1(B_0_1, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_2_1, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_3_1, vl);
        A_1_1 = __riscv_vxor_vv_u64m1(B_1_1, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_3_1, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_4_1, vl);
        A_2_1 = __riscv_vxor_vv_u64m1(B_2_1, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_4_1, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_0_1, vl);
        A_3_1 = __riscv_vxor_vv_u64m1(B_3_1, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_0_1, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_1_1, vl);
        A_4_1 = __riscv_vxor_vv_u64m1(B_4_1, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_1_2, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_2_2, vl);
        A_0_2 = __riscv_vxor_vv_u64m1(B_0_2, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_2_2, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_3_2, vl);
        A_1_2 = __riscv_vxor_vv_u64m1(B_1_2, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_3_2, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_4_2, vl);
        A_2_2 = __riscv_vxor_vv_u64m1(B_2_2, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_4_2, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_0_2, vl);
        A_3_2 = __riscv_vxor_vv_u64m1(B_3_2, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_0_2, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_1_2, vl);
        A_4_2 = __riscv_vxor_vv_u64m1(B_4_2, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_1_3, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_2_3, vl);
        A_0_3 = __riscv_vxor_vv_u64m1(B_0_3, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_2_3, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_3_3, vl);
        A_1_3 = __riscv_vxor_vv_u64m1(B_1_3, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_3_3, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_4_3, vl);
        A_2_3 = __riscv_vxor_vv_u64m1(B_2_3, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_4_3, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_0_3, vl);
        A_3_3 = __riscv_vxor_vv_u64m1(B_3_3, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_0_3, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_1_3, vl);
        A_4_3 = __riscv_vxor_vv_u64m1(B_4_3, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_1_4, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_2_4, vl);
        A_0_4 = __riscv_vxor_vv_u64m1(B_0_4, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_2_4, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_3_4, vl);
        A_1_4 = __riscv_vxor_vv_u64m1(B_1_4, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_3_4, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_4_4, vl);
        A_2_4 = __riscv_vxor_vv_u64m1(B_2_4, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_4_4, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_0_4, vl);
        A_3_4 = __riscv_vxor_vv_u64m1(B_3_4, and_tmp, vl);
        
        not_tmp = __riscv_vnot_v_u64m1(B_0_4, vl);
        and_tmp = __riscv_vand_vv_u64m1(not_tmp, B_1_4, vl);
        A_4_4 = __riscv_vxor_vv_u64m1(B_4_4, and_tmp, vl);
        
        // Iota step: A[0,0] ^= RC[round]
        A_0_0 = __riscv_vxor_vx_u64m1(A_0_0, RC[round], vl);
        
        // Store results back using strided store
        __riscv_vsse64_v_u64m1(&state[0], stride, A_0_0, vl);
        __riscv_vsse64_v_u64m1(&state[1], stride, A_0_1, vl);
        __riscv_vsse64_v_u64m1(&state[2], stride, A_0_2, vl);
        __riscv_vsse64_v_u64m1(&state[3], stride, A_0_3, vl);
        __riscv_vsse64_v_u64m1(&state[4], stride, A_0_4, vl);
        __riscv_vsse64_v_u64m1(&state[5], stride, A_1_0, vl);
        __riscv_vsse64_v_u64m1(&state[6], stride, A_1_1, vl);
        __riscv_vsse64_v_u64m1(&state[7], stride, A_1_2, vl);
        __riscv_vsse64_v_u64m1(&state[8], stride, A_1_3, vl);
        __riscv_vsse64_v_u64m1(&state[9], stride, A_1_4, vl);
        __riscv_vsse64_v_u64m1(&state[10], stride, A_2_0, vl);
        __riscv_vsse64_v_u64m1(&state[11], stride, A_2_1, vl);
        __riscv_vsse64_v_u64m1(&state[12], stride, A_2_2, vl);
        __riscv_vsse64_v_u64m1(&state[13], stride, A_2_3, vl);
        __riscv_vsse64_v_u64m1(&state[14], stride, A_2_4, vl);
        __riscv_vsse64_v_u64m1(&state[15], stride, A_3_0, vl);
        __riscv_vsse64_v_u64m1(&state[16], stride, A_3_1, vl);
        __riscv_vsse64_v_u64m1(&state[17], stride, A_3_2, vl);
        __riscv_vsse64_v_u64m1(&state[18], stride, A_3_3, vl);
        __riscv_vsse64_v_u64m1(&state[19], stride, A_3_4, vl);
        __riscv_vsse64_v_u64m1(&state[20], stride, A_4_0, vl);
        __riscv_vsse64_v_u64m1(&state[21], stride, A_4_1, vl);
        __riscv_vsse64_v_u64m1(&state[22], stride, A_4_2, vl);
        __riscv_vsse64_v_u64m1(&state[23], stride, A_4_3, vl);
        __riscv_vsse64_v_u64m1(&state[24], stride, A_4_4, vl);
    }
}

/* Wrapper that calls x4 vector version on the 4 states */
void KeccakP1600_StatePermute_x4_vector_wrapper(uint64_t *state)
{
    KeccakP1600_StatePermute_x4_vector(state);
}

#else /* !__riscv_vector */

MLD_EMPTY_CU(KeccakP_1600_rv64_x4_vector)

#endif /* __riscv_vector */
