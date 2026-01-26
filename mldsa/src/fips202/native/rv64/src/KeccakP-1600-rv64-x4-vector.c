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
    return __riscv_vor_vv_u64m1(__riscv_vsrl_vx_u64m1(v, shamt, vl), __riscv_vsll_vx_u64m1(v, 64 - shamt, vl), vl);
}

static inline vuint64m1_t __riscv_vror_vv_u64m1(vuint64m1_t v, vuint64m1_t shamt, size_t vl)
{
    return __riscv_vor_vv_u64m1(__riscv_vsrl_vv_u64m1(v, shamt, vl), __riscv_vsll_vv_u64m1(v, __riscv_vrsub_vx_u64m1(shamt, 64, vl), vl), vl);
}

/** RISC-V vector rotate left (if Zvkb is not implemented, can be emulated with RVV 1.0 operations) */
static inline vuint64m1_t __riscv_vrol_vx_u64m1(vuint64m1_t v, uint64_t shamt, size_t vl)
{
    return __riscv_vor_vv_u64m1(__riscv_vsll_vx_u64m1(v, shamt, vl), __riscv_vsrl_vx_u64m1(v, 64 - shamt, vl), vl);
}

static inline vuint64m1_t __riscv_vrol_vv_u64m1(vuint64m1_t v, vuint64m1_t shamt, size_t vl)
{
    return __riscv_vor_vv_u64m1(__riscv_vsll_vv_u64m1(v, shamt, vl), __riscv_vsrl_vv_u64m1(v, __riscv_vrsub_vx_u64m1(shamt, 64, vl), vl), vl);
}
	
/* RVV-based x4 vectorized Keccak permutation
 * Processes 4 Keccak states in parallel using RISC-V Vector extension
 * state: pointer to array of 4*25 uint64_t elements (100 elements total)
 *        organized as state[0..24] for first state, state[25..49] for second, etc.
 *        States are CONTIGUOUS, not interleaved.
 */
void KeccakP1600_StatePermute_x4_vector(uint64_t *state)
{
    size_t avl = 4; // 4 elements should be processed at a time
    const ptrdiff_t stride = MLD_KECCAK_LANES * sizeof(uint64_t); // 25 * 8 = 200 bytes

    #define load_lane(x, y) __riscv_vlse64_v_u64m1(&state[(x) + 5 * (y)], stride, vl)

    for (; avl > 0;) {
        size_t vl = __riscv_vsetvl_e64m1(avl); // Process 4 elements at a time
        // prolog: loading state
        // u64 A_0_0 = rL(0, 0);
        vuint64m1_t A_0_0 = load_lane(0, 0);
        // u64 A_0_1 = rL(0, 1);
        vuint64m1_t A_0_1 = load_lane(0, 1);
        // u64 A_0_2 = rL(0, 2);
        vuint64m1_t A_0_2 = load_lane(0, 2);
        // u64 A_0_3 = rL(0, 3);
        vuint64m1_t A_0_3 = load_lane(0, 3);
        // u64 A_0_4 = rL(0, 4);
        vuint64m1_t A_0_4 = load_lane(0, 4);
        // u64 A_1_0 = rL(1, 0);
        vuint64m1_t A_1_0 = load_lane(1, 0);
        // u64 A_1_1 = rL(1, 1);
        vuint64m1_t A_1_1 = load_lane(1, 1);
        // u64 A_1_2 = rL(1, 2);
        vuint64m1_t A_1_2 = load_lane(1, 2);
        // u64 A_1_3 = rL(1, 3);
        vuint64m1_t A_1_3 = load_lane(1, 3);
        // u64 A_1_4 = rL(1, 4);
        vuint64m1_t A_1_4 = load_lane(1, 4);
        // u64 A_2_0 = rL(2, 0);
        vuint64m1_t A_2_0 = load_lane(2, 0);
        // u64 A_2_1 = rL(2, 1);
        vuint64m1_t A_2_1 = load_lane(2, 1);
        // u64 A_2_2 = rL(2, 2);
        vuint64m1_t A_2_2 = load_lane(2, 2);
        // u64 A_2_3 = rL(2, 3);
        vuint64m1_t A_2_3 = load_lane(2, 3);
        // u64 A_2_4 = rL(2, 4);
        vuint64m1_t A_2_4 = load_lane(2, 4);
        // u64 A_3_0 = rL(3, 0);
        vuint64m1_t A_3_0 = load_lane(3, 0);
        // u64 A_3_1 = rL(3, 1);
        vuint64m1_t A_3_1 = load_lane(3, 1);
        // u64 A_3_2 = rL(3, 2);
        vuint64m1_t A_3_2 = load_lane(3, 2);
        // u64 A_3_3 = rL(3, 3);
        vuint64m1_t A_3_3 = load_lane(3, 3);
        // u64 A_3_4 = rL(3, 4);
        vuint64m1_t A_3_4 = load_lane(3, 4);
        // u64 A_4_0 = rL(4, 0);
        vuint64m1_t A_4_0 = load_lane(4, 0);
        // u64 A_4_1 = rL(4, 1);
        vuint64m1_t A_4_1 = load_lane(4, 1);
        // u64 A_4_2 = rL(4, 2);
        vuint64m1_t A_4_2 = load_lane(4, 2);
        // u64 A_4_3 = rL(4, 3);
        vuint64m1_t A_4_3 = load_lane(4, 3);
        // u64 A_4_4 = rL(4, 4);
        vuint64m1_t A_4_4 = load_lane(4, 4);
        
        for (unsigned int round = 0; round < NROUNDS; round++)
        {
            // u64 C_0= A_0_0 ^ A_0_1 ^ A_0_2 ^ A_0_3 ^ A_0_4;
            vuint64m1_t C_0 = __riscv_vxor_vv_u64m1(__riscv_vxor_vv_u64m1(A_0_0, A_0_1, vl), __riscv_vxor_vv_u64m1(A_0_2, __riscv_vxor_vv_u64m1(A_0_3, A_0_4, vl), vl), vl);
            // u64 C_1= A_1_0 ^ A_1_1 ^ A_1_2 ^ A_1_3 ^ A_1_4;
            vuint64m1_t C_1 = __riscv_vxor_vv_u64m1(__riscv_vxor_vv_u64m1(A_1_0, A_1_1, vl), __riscv_vxor_vv_u64m1(A_1_2, __riscv_vxor_vv_u64m1(A_1_3, A_1_4, vl), vl), vl);
            // u64 C_2= A_2_0 ^ A_2_1 ^ A_2_2 ^ A_2_3 ^ A_2_4;
            vuint64m1_t C_2 = __riscv_vxor_vv_u64m1(__riscv_vxor_vv_u64m1(A_2_0, A_2_1, vl), __riscv_vxor_vv_u64m1(A_2_2, __riscv_vxor_vv_u64m1(A_2_3, A_2_4, vl), vl), vl);
            // u64 C_3= A_3_0 ^ A_3_1 ^ A_3_2 ^ A_3_3 ^ A_3_4;
            vuint64m1_t C_3 = __riscv_vxor_vv_u64m1(__riscv_vxor_vv_u64m1(A_3_0, A_3_1, vl), __riscv_vxor_vv_u64m1(A_3_2, __riscv_vxor_vv_u64m1(A_3_3, A_3_4, vl), vl), vl);
            // u64 C_4= A_4_0 ^ A_4_1 ^ A_4_2 ^ A_4_3 ^ A_4_4;
            vuint64m1_t C_4 = __riscv_vxor_vv_u64m1(__riscv_vxor_vv_u64m1(A_4_0, A_4_1, vl), __riscv_vxor_vv_u64m1(A_4_2, __riscv_vxor_vv_u64m1(A_4_3, A_4_4, vl), vl), vl);
            // u64 D_0 = C_4 ^ ROL(C_1,1);
            vuint64m1_t D_0 = __riscv_vxor_vv_u64m1(C_4, __riscv_vrol_vx_u64m1(C_1, 1, vl), vl);
            // A_0_0 ^= D_0;
            A_0_0 = __riscv_vxor_vv_u64m1(A_0_0, D_0, vl);
            // A_0_1 ^= D_0;
            A_0_1 = __riscv_vxor_vv_u64m1(A_0_1, D_0, vl);
            // A_0_2 ^= D_0;
            A_0_2 = __riscv_vxor_vv_u64m1(A_0_2, D_0, vl);
            // A_0_3 ^= D_0;
            A_0_3 = __riscv_vxor_vv_u64m1(A_0_3, D_0, vl);
            // A_0_4 ^= D_0;
            A_0_4 = __riscv_vxor_vv_u64m1(A_0_4, D_0, vl);
            // u64 D_1 = C_0 ^ ROL(C_2,1);
            vuint64m1_t D_1 = __riscv_vxor_vv_u64m1(C_0, __riscv_vrol_vx_u64m1(C_2, 1, vl), vl);
            // A_1_0 ^= D_1;
            A_1_0 = __riscv_vxor_vv_u64m1(A_1_0, D_1, vl);
            // A_1_1 ^= D_1;
            A_1_1 = __riscv_vxor_vv_u64m1(A_1_1, D_1, vl);
            // A_1_2 ^= D_1;
            A_1_2 = __riscv_vxor_vv_u64m1(A_1_2, D_1, vl);
            // A_1_3 ^= D_1;
            A_1_3 = __riscv_vxor_vv_u64m1(A_1_3, D_1, vl);
            // A_1_4 ^= D_1;
            A_1_4 = __riscv_vxor_vv_u64m1(A_1_4, D_1, vl);
            // u64 D_2 = C_1 ^ ROL(C_3,1);
            vuint64m1_t D_2 = __riscv_vxor_vv_u64m1(C_1, __riscv_vrol_vx_u64m1(C_3, 1, vl), vl);
            // A_2_0 ^= D_2;
            A_2_0 = __riscv_vxor_vv_u64m1(A_2_0, D_2, vl);
            // A_2_1 ^= D_2;
            A_2_1 = __riscv_vxor_vv_u64m1(A_2_1, D_2, vl);
            // A_2_2 ^= D_2;
            A_2_2 = __riscv_vxor_vv_u64m1(A_2_2, D_2, vl);
            // A_2_3 ^= D_2;
            A_2_3 = __riscv_vxor_vv_u64m1(A_2_3, D_2, vl);
            // A_2_4 ^= D_2;
            A_2_4 = __riscv_vxor_vv_u64m1(A_2_4, D_2, vl);
            // u64 D_3 = C_2 ^ ROL(C_4,1);
            vuint64m1_t D_3 = __riscv_vxor_vv_u64m1(C_2, __riscv_vrol_vx_u64m1(C_4, 1, vl), vl);
            // A_3_0 ^= D_3;
            A_3_0 = __riscv_vxor_vv_u64m1(A_3_0, D_3, vl);
            // A_3_1 ^= D_3;
            A_3_1 = __riscv_vxor_vv_u64m1(A_3_1, D_3, vl);
            // A_3_2 ^= D_3;
            A_3_2 = __riscv_vxor_vv_u64m1(A_3_2, D_3, vl);
            // A_3_3 ^= D_3;
            A_3_3 = __riscv_vxor_vv_u64m1(A_3_3, D_3, vl);
            // A_3_4 ^= D_3;
            A_3_4 = __riscv_vxor_vv_u64m1(A_3_4, D_3, vl);
            // u64 D_4 = C_3 ^ ROL(C_0,1);
            vuint64m1_t D_4 = __riscv_vxor_vv_u64m1(C_3, __riscv_vrol_vx_u64m1(C_0, 1, vl), vl);
            // A_4_0 ^= D_4;
            A_4_0 = __riscv_vxor_vv_u64m1(A_4_0, D_4, vl);
            // A_4_1 ^= D_4;
            A_4_1 = __riscv_vxor_vv_u64m1(A_4_1, D_4, vl);
            // A_4_2 ^= D_4;
            A_4_2 = __riscv_vxor_vv_u64m1(A_4_2, D_4, vl);
            // A_4_3 ^= D_4;
            A_4_3 = __riscv_vxor_vv_u64m1(A_4_3, D_4, vl);
            // A_4_4 ^= D_4;
            A_4_4 = __riscv_vxor_vv_u64m1(A_4_4, D_4, vl);
            // u64 T_0 = A_1_0;
            vuint64m1_t T_0 = A_1_0;
            // u64 T_1 = A_0_2;
            vuint64m1_t T_1 = A_0_2;
            // A_0_2 = ROL(T_0, 1);
            A_0_2 = __riscv_vrol_vx_u64m1(T_0, 1, vl);
            // u64 T_2 = A_2_1;
            vuint64m1_t T_2 = A_2_1;
            // A_2_1 = ROL(T_1, 3);
            A_2_1 = __riscv_vrol_vx_u64m1(T_1, 3, vl);
            // u64 T_3 = A_1_2;
            vuint64m1_t T_3 = A_1_2;
            // A_1_2 = ROL(T_2, 6);
            A_1_2 = __riscv_vrol_vx_u64m1(T_2, 6, vl);
            // u64 T_4 = A_2_3;
            vuint64m1_t T_4 = A_2_3;
            // A_2_3 = ROL(T_3, 10);
            A_2_3 = __riscv_vrol_vx_u64m1(T_3, 10, vl);
            // u64 T_5 = A_3_3;
            vuint64m1_t T_5 = A_3_3;
            // A_3_3 = ROL(T_4, 15);
            A_3_3 = __riscv_vrol_vx_u64m1(T_4, 15, vl);
            // u64 T_6 = A_3_0;
            vuint64m1_t T_6 = A_3_0;
            // A_3_0 = ROL(T_5, 21);
            A_3_0 = __riscv_vrol_vx_u64m1(T_5, 21, vl);
            // u64 T_7 = A_0_1;
            vuint64m1_t T_7 = A_0_1;
            // A_0_1 = ROL(T_6, 28);
            A_0_1 = __riscv_vrol_vx_u64m1(T_6, 28, vl);
            // u64 T_8 = A_1_3;
            vuint64m1_t T_8 = A_1_3;
            // A_1_3 = ROL(T_7, 36);
            A_1_3 = __riscv_vrol_vx_u64m1(T_7, 36, vl);
            // u64 T_9 = A_3_1;
            vuint64m1_t T_9 = A_3_1;
            // A_3_1 = ROL(T_8, 45);
            A_3_1 = __riscv_vrol_vx_u64m1(T_8, 45, vl);
            // u64 T_10 = A_1_4;
            vuint64m1_t T_10 = A_1_4;
            // A_1_4 = ROL(T_9, 55);
            A_1_4 = __riscv_vrol_vx_u64m1(T_9, 55, vl);
            // u64 T_11 = A_4_4;
            vuint64m1_t T_11 = A_4_4;
            // A_4_4 = ROL(T_10, 2);
            A_4_4 = __riscv_vrol_vx_u64m1(T_10, 2, vl);
            // u64 T_12 = A_4_0;
            vuint64m1_t T_12 = A_4_0;
            // A_4_0 = ROL(T_11, 14);
            A_4_0 = __riscv_vrol_vx_u64m1(T_11, 14, vl);
            // u64 T_13 = A_0_3;
            vuint64m1_t T_13 = A_0_3;
            // A_0_3 = ROL(T_12, 27);
            A_0_3 = __riscv_vrol_vx_u64m1(T_12, 27, vl);
            // u64 T_14 = A_3_4;
            vuint64m1_t T_14 = A_3_4;
            // A_3_4 = ROL(T_13, 41);
            A_3_4 = __riscv_vrol_vx_u64m1(T_13, 41, vl);
            // u64 T_15 = A_4_3;
            vuint64m1_t T_15 = A_4_3;
            // A_4_3 = ROL(T_14, 56);
            A_4_3 = __riscv_vrol_vx_u64m1(T_14, 56, vl);
            // u64 T_16 = A_3_2;
            vuint64m1_t T_16 = A_3_2;
            // A_3_2 = ROL(T_15, 8);
            A_3_2 = __riscv_vrol_vx_u64m1(T_15, 8, vl);
            // u64 T_17 = A_2_2;
            vuint64m1_t T_17 = A_2_2;
            // A_2_2 = ROL(T_16, 25);
            A_2_2 = __riscv_vrol_vx_u64m1(T_16, 25, vl);
            // u64 T_18 = A_2_0;
            vuint64m1_t T_18 = A_2_0;
            // A_2_0 = ROL(T_17, 43);
            A_2_0 = __riscv_vrol_vx_u64m1(T_17, 43, vl);
            // u64 T_19 = A_0_4;
            vuint64m1_t T_19 = A_0_4;
            // A_0_4 = ROL(T_18, 62);
            A_0_4 = __riscv_vrol_vx_u64m1(T_18, 62, vl);
            // u64 T_20 = A_4_2;
            vuint64m1_t T_20 = A_4_2;
            // A_4_2 = ROL(T_19, 18);
            A_4_2 = __riscv_vrol_vx_u64m1(T_19, 18, vl);
            // u64 T_21 = A_2_4;
            vuint64m1_t T_21 = A_2_4;
            // A_2_4 = ROL(T_20, 39);
            A_2_4 = __riscv_vrol_vx_u64m1(T_20, 39, vl);
            // u64 T_22 = A_4_1;
            vuint64m1_t T_22 = A_4_1;
            // A_4_1 = ROL(T_21, 61);
            A_4_1 = __riscv_vrol_vx_u64m1(T_21, 61, vl);
            // u64 T_23 = A_1_1;
            vuint64m1_t T_23 = A_1_1;
            // A_1_1 = ROL(T_22, 20);
            A_1_1 = __riscv_vrol_vx_u64m1(T_22, 20, vl);
            // // u64 T_24 = A_1_0;
            // A_1_0 = ROL(T_23, 44);
            vuint64m1_t T_24 = A_1_0;
            A_1_0 = __riscv_vrol_vx_u64m1(T_23, 44, vl);
            // u64 C_0_0 = A_0_0;
            vuint64m1_t C_0_0 = A_0_0;
            // u64 C_0_1 = A_1_0;
            vuint64m1_t C_0_1 = A_1_0;
            // u64 C_0_2 = A_2_0;
            vuint64m1_t C_0_2 = A_2_0;
            // u64 C_0_3 = A_3_0;
            vuint64m1_t C_0_3 = A_3_0;
            // u64 C_0_4 = A_4_0;
            vuint64m1_t C_0_4 = A_4_0;
            // A_0_0 = C_0_0 ^ (~C_0_1 & C_0_2);
            A_0_0 = __riscv_vxor_vv_u64m1(C_0_0, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_0_1, vl), C_0_2, vl), vl);
            // A_1_0 = C_0_1 ^ (~C_0_2 & C_0_3);
            A_1_0 = __riscv_vxor_vv_u64m1(C_0_1, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_0_2, vl), C_0_3, vl), vl);
            // A_2_0 = C_0_2 ^ (~C_0_3 & C_0_4);
            A_2_0 = __riscv_vxor_vv_u64m1(C_0_2, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_0_3, vl), C_0_4, vl), vl);
            // A_3_0 = C_0_3 ^ (~C_0_4 & C_0_0);
            A_3_0 = __riscv_vxor_vv_u64m1(C_0_3, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_0_4, vl), C_0_0, vl), vl);
            // A_4_0 = C_0_4 ^ (~C_0_0 & C_0_1);
            A_4_0 = __riscv_vxor_vv_u64m1(C_0_4, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_0_0, vl), C_0_1, vl), vl);
            // u64 C_1_0 = A_0_1;
            vuint64m1_t C_1_0 = A_0_1;
            // u64 C_1_1 = A_1_1;
            vuint64m1_t C_1_1 = A_1_1;
            // u64 C_1_2 = A_2_1;
            vuint64m1_t C_1_2 = A_2_1;
            // u64 C_1_3 = A_3_1;
            vuint64m1_t C_1_3 = A_3_1;
            // u64 C_1_4 = A_4_1;
            vuint64m1_t C_1_4 = A_4_1;
            // A_0_1 = C_1_0 ^ (~C_1_1 & C_1_2);
            A_0_1 = __riscv_vxor_vv_u64m1(C_1_0, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_1_1, vl), C_1_2, vl), vl);
            // A_1_1 = C_1_1 ^ (~C_1_2 & C_1_3);
            A_1_1 = __riscv_vxor_vv_u64m1(C_1_1, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_1_2, vl), C_1_3, vl), vl);
            // A_2_1 = C_1_2 ^ (~C_1_3 & C_1_4);
            A_2_1 = __riscv_vxor_vv_u64m1(C_1_2, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_1_3, vl), C_1_4, vl), vl);
            // A_3_1 = C_1_3 ^ (~C_1_4 & C_1_0);
            A_3_1 = __riscv_vxor_vv_u64m1(C_1_3, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_1_4, vl), C_1_0, vl), vl);
            // A_4_1 = C_1_4 ^ (~C_1_0 & C_1_1);
            A_4_1 = __riscv_vxor_vv_u64m1(C_1_4, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_1_0, vl), C_1_1, vl), vl);
            // u64 C_2_0 = A_0_2;
            vuint64m1_t C_2_0 = A_0_2;
            // u64 C_2_1 = A_1_2;
            vuint64m1_t C_2_1 = A_1_2;
            // u64 C_2_2 = A_2_2;
            vuint64m1_t C_2_2 = A_2_2;
            // u64 C_2_3 = A_3_2;
            vuint64m1_t C_2_3 = A_3_2;
            // u64 C_2_4 = A_4_2;
            vuint64m1_t C_2_4 = A_4_2;
            // A_0_2 = C_2_0 ^ (~C_2_1 & C_2_2);
            A_0_2 = __riscv_vxor_vv_u64m1(C_2_0, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_2_1, vl), C_2_2, vl), vl);
            // A_1_2 = C_2_1 ^ (~C_2_2 & C_2_3);
            A_1_2 = __riscv_vxor_vv_u64m1(C_2_1, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_2_2, vl), C_2_3, vl), vl);
            // A_2_2 = C_2_2 ^ (~C_2_3 & C_2_4);
            A_2_2 = __riscv_vxor_vv_u64m1(C_2_2, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_2_3, vl), C_2_4, vl), vl);
            // A_3_2 = C_2_3 ^ (~C_2_4 & C_2_0);
            A_3_2 = __riscv_vxor_vv_u64m1(C_2_3, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_2_4, vl), C_2_0, vl), vl);
            // A_4_2 = C_2_4 ^ (~C_2_0 & C_2_1);
            A_4_2 = __riscv_vxor_vv_u64m1(C_2_4, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_2_0, vl), C_2_1, vl), vl);
            // u64 C_3_0 = A_0_3;
            vuint64m1_t C_3_0 = A_0_3;
            // u64 C_3_1 = A_1_3;
            vuint64m1_t C_3_1 = A_1_3;
            // u64 C_3_2 = A_2_3;
            vuint64m1_t C_3_2 = A_2_3;
            // u64 C_3_3 = A_3_3;
            vuint64m1_t C_3_3 = A_3_3;
            // u64 C_3_4 = A_4_3;
            vuint64m1_t C_3_4 = A_4_3;
            // A_0_3 = C_3_0 ^ (~C_3_1 & C_3_2);
            A_0_3 = __riscv_vxor_vv_u64m1(C_3_0, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_3_1, vl), C_3_2, vl), vl);
            // A_1_3 = C_3_1 ^ (~C_3_2 & C_3_3);
            A_1_3 = __riscv_vxor_vv_u64m1(C_3_1, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_3_2, vl), C_3_3, vl), vl);
            // A_2_3 = C_3_2 ^ (~C_3_3 & C_3_4);
            A_2_3 = __riscv_vxor_vv_u64m1(C_3_2, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_3_3, vl), C_3_4, vl), vl);
            // A_3_3 = C_3_3 ^ (~C_3_4 & C_3_0);
            A_3_3 = __riscv_vxor_vv_u64m1(C_3_3, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_3_4, vl), C_3_0, vl), vl);
            // A_4_3 = C_3_4 ^ (~C_3_0 & C_3_1);
            A_4_3 = __riscv_vxor_vv_u64m1(C_3_4, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_3_0, vl), C_3_1, vl), vl);
            // u64 C_4_0 = A_0_4;
            vuint64m1_t C_4_0 = A_0_4;
            // u64 C_4_1 = A_1_4;
            vuint64m1_t C_4_1 = A_1_4;
            // u64 C_4_2 = A_2_4;
            vuint64m1_t C_4_2 = A_2_4;
            // u64 C_4_3 = A_3_4;
            vuint64m1_t C_4_3 = A_3_4;
            // u64 C_4_4 = A_4_4;
            vuint64m1_t C_4_4 = A_4_4;
            // A_0_4 = C_4_0 ^ (~C_4_1 & C_4_2);
            A_0_4 = __riscv_vxor_vv_u64m1(C_4_0, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_4_1, vl), C_4_2, vl), vl);
            // A_1_4 = C_4_1 ^ (~C_4_2 & C_4_3);
            A_1_4 = __riscv_vxor_vv_u64m1(C_4_1, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_4_2, vl), C_4_3, vl), vl);
            // A_2_4 = C_4_2 ^ (~C_4_3 & C_4_4);
            A_2_4 = __riscv_vxor_vv_u64m1(C_4_2, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_4_3, vl), C_4_4, vl), vl);
            // A_3_4 = C_4_3 ^ (~C_4_4 & C_4_0);
            A_3_4 = __riscv_vxor_vv_u64m1(C_4_3, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_4_4, vl), C_4_0, vl), vl);
            // A_4_4 = C_4_4 ^ (~C_4_0 & C_4_1);
            A_4_4 = __riscv_vxor_vv_u64m1(C_4_4, __riscv_vand_vv_u64m1(__riscv_vnot_u64m1(C_4_0, vl), C_4_1, vl), vl);
            // /*ι*/ // XL(0,0,RC[i]);
            // A_0_0 ^= RC[i];
            // using tail undisturbed policy to make sure only the first element is modified
            A_0_0 = __riscv_vxor_vv_u64m1_tu(A_0_0, RC[round], 1);
            
        }
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


        // updating avl
        avl -= vl;
        state += MLD_KECCAK_LANES * vl;

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
