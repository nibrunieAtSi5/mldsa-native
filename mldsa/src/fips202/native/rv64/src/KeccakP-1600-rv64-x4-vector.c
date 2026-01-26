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
        vuint64m1_t C[5];
        for (int x = 0; x < 5; x++)
        {
            // Load A[x,0] from all 4 states using strided load
            C[x] = __riscv_vlse64_v_u64m1(&state[x*5 + 0], stride, vl);
            
            // XOR with A[x,y] for y = 1..4
            for (int y = 1; y < 5; y++)
            {
                vuint64m1_t lane = __riscv_vlse64_v_u64m1(&state[x*5 + y], stride, vl);
                C[x] = __riscv_vxor_vv_u64m1(C[x], lane, vl);
            }
        }
        
        // Compute D values: D[x] = C[x-1] ^ ROL(C[x+1], 1)
        vuint64m1_t D[5];
        for (int x = 0; x < 5; x++)
        {
            vuint64m1_t rotated = __riscv_vror_vx_u64m1(C[(x + 1) % 5], 63, vl); // ROL by 1 = ROR by 63
            D[x] = __riscv_vxor_vv_u64m1(C[(x + 4) % 5], rotated, vl);
        }
        
        // Apply theta and load state into registers: A[x,y] ^= D[x]
        vuint64m1_t A[5][5];
        for (int x = 0; x < 5; x++)
        {
            for (int y = 0; y < 5; y++)
            {
                A[x][y] = __riscv_vlse64_v_u64m1(&state[x*5 + y], stride, vl);
                A[x][y] = __riscv_vxor_vv_u64m1(A[x][y], D[x], vl);
            }
        }
        
        // Rho and Pi steps combined: B[y, 2x+3y] = ROL(A[x,y], r[x,y])
        const int rho_offsets[5][5] = {
            {0,  1,  62, 28, 27},
            {36, 44, 6,  55, 20},
            {3,  10, 43, 25, 39},
            {41, 45, 15, 21, 8},
            {18, 2,  61, 56, 14}
        };
        
        vuint64m1_t B[5][5];
        for (int x = 0; x < 5; x++)
        {
            for (int y = 0; y < 5; y++)
            {
                int newX = y;
                int newY = (2*x + 3*y) % 5;
                int offset = rho_offsets[x][y];
                
                if (offset == 0)
                {
                    B[newX][newY] = A[x][y];
                }
                else
                {
                    B[newX][newY] = __riscv_vror_vx_u64m1(A[x][y], 64 - offset, vl);
                }
            }
        }
        
        // Chi step: A[x,y] = B[x,y] ^ ((~B[x+1,y]) & B[x+2,y])
        for (int x = 0; x < 5; x++)
        {
            for (int y = 0; y < 5; y++)
            {
                vuint64m1_t not_b1 = __riscv_vnot_v_u64m1(B[(x+1)%5][y], vl);
                vuint64m1_t and_result = __riscv_vand_vv_u64m1(not_b1, B[(x+2)%5][y], vl);
                A[x][y] = __riscv_vxor_vv_u64m1(B[x][y], and_result, vl);
            }
        }
        
        // Iota step: A[0,0] ^= RC[round]
        A[0][0] = __riscv_vxor_vx_u64m1(A[0][0], RC[round], vl);
        
        // Store results back using strided store
        for (int x = 0; x < 5; x++)
        {
            for (int y = 0; y < 5; y++)
            {
                __riscv_vsse64_v_u64m1(&state[x*5 + y], stride, A[x][y], vl);
            }
        }
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


