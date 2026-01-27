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


// It looks like gcc has already a definition of this (alias) intrinsic and complains
// of a shadowed definition if it gets redefined
#if defined(__clang)
static inline vuint64m1_t __riscv_vnot_v_u64m1(vuint64m1_t v, size_t vl)
{
    return __riscv_vxor_vx_u64m1(v, UINT64_MAX, vl);
}
#endif


/** RISC-V vector rotate right (if Zvkb is not implemented, can be emulated with RVV 1.0 operations) */
__attribute__((unused)) static inline vuint64m1_t __riscv_vror_vx_u64m1(vuint64m1_t v, uint64_t shamt, size_t vl)
{
    return __riscv_vor_vv_u64m1(__riscv_vsrl_vx_u64m1(v, shamt, vl), __riscv_vsll_vx_u64m1(v, 64 - shamt, vl), vl);
}

__attribute__((unused)) static inline vuint64m1_t __riscv_vror_vv_u64m1(vuint64m1_t v, vuint64m1_t shamt, size_t vl)
{
    return __riscv_vor_vv_u64m1(__riscv_vsrl_vv_u64m1(v, shamt, vl), __riscv_vsll_vv_u64m1(v, __riscv_vrsub_vx_u64m1(shamt, 64, vl), vl), vl);
}

/** RISC-V vector rotate left (if Zvkb is not implemented, can be emulated with RVV 1.0 operations) */
static inline vuint64m1_t __riscv_vrol_vx_u64m1(vuint64m1_t v, uint64_t shamt, size_t vl)
{
    return __riscv_vor_vv_u64m1(__riscv_vsll_vx_u64m1(v, shamt, vl), __riscv_vsrl_vx_u64m1(v, 64 - shamt, vl), vl);
}

__attribute__((unused)) static inline vuint64m1_t __riscv_vrol_vv_u64m1(vuint64m1_t v, vuint64m1_t shamt, size_t vl)
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
    #define store_lane(x, y, value) __riscv_vsse64_v_u64m1(&state[(x) + 5 * (y)], stride, value, vl)

    for (; avl > 0;) {
        size_t vl = __riscv_vsetvl_e64m1(avl); // Process 4 elements at a time
        // prolog: loading state
        // uint64_t Aba, Abe, Abi, Abo, Abu;
        vuint64m1_t Aba, Abe, Abi, Abo, Abu;
        // uint64_t Aga, Age, Agi, Ago, Agu;
        vuint64m1_t Aga, Age, Agi, Ago, Agu;
        // uint64_t Aka, Ake, Aki, Ako, Aku;
        vuint64m1_t Aka, Ake, Aki, Ako, Aku;
        // uint64_t Ama, Ame, Ami, Amo, Amu;
        vuint64m1_t Ama, Ame, Ami, Amo, Amu;
        // uint64_t Asa, Ase, Asi, Aso, Asu;
        vuint64m1_t Asa, Ase, Asi, Aso, Asu;
        // uint64_t BCa, BCe, BCi, BCo, BCu;
        vuint64m1_t BCa, BCe, BCi, BCo, BCu;
        // uint64_t Da, De, Di, Do, Du;
        vuint64m1_t Da, De, Di, Do, Du;
        // uint64_t Eba, Ebe, Ebi, Ebo, Ebu;
        vuint64m1_t Eba, Ebe, Ebi, Ebo, Ebu;
        // uint64_t Ega, Ege, Egi, Ego, Egu;
        vuint64m1_t Ega, Ege, Egi, Ego, Egu;
        // uint64_t Eka, Eke, Eki, Eko, Eku;
        vuint64m1_t Eka, Eke, Eki, Eko, Eku;
        // uint64_t Ema, Eme, Emi, Emo, Emu;
        vuint64m1_t Ema, Eme, Emi, Emo, Emu;
        // uint64_t Esa, Ese, Esi, Eso, Esu;
        vuint64m1_t Esa, Ese, Esi, Eso, Esu;

        // /* Load state */
        // Aba = state[0];
        Aba = __riscv_vlse64_v_u64m1(&state[0], stride, vl);
        // Abe = state[1];
        Abe = __riscv_vlse64_v_u64m1(&state[1], stride, vl);
        // Abi = state[2];
        Abi = __riscv_vlse64_v_u64m1(&state[2], stride, vl);
        // Abo = state[3];
        Abo = __riscv_vlse64_v_u64m1(&state[3], stride, vl);
        // Abu = state[4];
        Abu = __riscv_vlse64_v_u64m1(&state[4], stride, vl);
        // Aga = state[5];
        Aga = __riscv_vlse64_v_u64m1(&state[5], stride, vl);
        // Age = state[6];
        Age = __riscv_vlse64_v_u64m1(&state[6], stride, vl);
        // Agi = state[7];
        Agi = __riscv_vlse64_v_u64m1(&state[7], stride, vl);
        // Ago = state[8];
        Ago = __riscv_vlse64_v_u64m1(&state[8], stride, vl);
        // Agu = state[9];
        Agu = __riscv_vlse64_v_u64m1(&state[9], stride, vl);
        // Aka = state[10];
        Aka = __riscv_vlse64_v_u64m1(&state[10], stride, vl);
        // Ake = state[11];
        Ake = __riscv_vlse64_v_u64m1(&state[11], stride, vl);
        // Aki = state[12];
        Aki = __riscv_vlse64_v_u64m1(&state[12], stride, vl);
        // Ako = state[13];
        Ako = __riscv_vlse64_v_u64m1(&state[13], stride, vl);
        // Aku = state[14];
        Aku = __riscv_vlse64_v_u64m1(&state[14], stride, vl);
        // Ama = state[15];
        Ama = __riscv_vlse64_v_u64m1(&state[15], stride, vl);
        // Ame = state[16];
        Ame = __riscv_vlse64_v_u64m1(&state[16], stride, vl);
        // Ami = state[17];
        Ami = __riscv_vlse64_v_u64m1(&state[17], stride, vl);
        // Asa = state[20];
        Asa = __riscv_vlse64_v_u64m1(&state[20], stride, vl);
        // Ase = state[21];
        Ase = __riscv_vlse64_v_u64m1(&state[21], stride, vl);
        // Asi = state[22];
        Asi = __riscv_vlse64_v_u64m1(&state[22], stride, vl);
        // Aso = state[23];
        Aso = __riscv_vlse64_v_u64m1(&state[23], stride, vl);
        // Asu = state[24];
        Asu = __riscv_vlse64_v_u64m1(&state[24], stride, vl);            


        for (round = 0; round < NROUNDS; round += 2)
        {
            // /* prepareTheta */
            // BCa = Aba ^ Aga ^ Aka ^ Ama ^ Asa;
            Bca = __riscv_vxor_vv_u64m1(Aba, Aga, vl);
            Bca = __riscv_vxor_vv_u64m1(Bca, Aka, vl);
            Bca = __riscv_vxor_vv_u64m1(Bca, Ama, vl);
            Bca = __riscv_vxor_vv_u64m1(Bca, Asa, vl);
            // BCe = Abe ^ Age ^ Ake ^ Ame ^ Ase;
            Bce = __riscv_vxor_vv_u64m1(Abe, Age, vl);
            Bce = __riscv_vxor_vv_u64m1(Bce, Ake, vl);
            Bce = __riscv_vxor_vv_u64m1(Bce, Ame, vl);
            Bce = __riscv_vxor_vv_u64m1(Bce, Ase, vl);
            // BCi = Abi ^ Agi ^ Aki ^ Ami ^ Asi;
            Bci = __riscv_vxor_vv_u64m1(Abi, Agi, vl);
            Bci = __riscv_vxor_vv_u64m1(Bci, Aki, vl);
            Bci = __riscv_vxor_vv_u64m1(Bci, Ami, vl);
            Bci = __riscv_vxor_vv_u64m1(Bci, Asi, vl);
            // BCo = Abo ^ Ago ^ Ako ^ Amo ^ Aso;
            Bco = __riscv_vxor_vv_u64m1(Abo, Ago, vl);
            Bco = __riscv_vxor_vv_u64m1(Bco, Ako, vl);
            Bco = __riscv_vxor_vv_u64m1(Bco, Amo, vl);
            Bco = __riscv_vxor_vv_u64m1(Bco, Aso, vl);
            // BCu = Abu ^ Agu ^ Aku ^ Amu ^ Asu;
            Bcu = __riscv_vxor_vv_u64m1(Abu, Agu, vl);
            Bcu = __riscv_vxor_vv_u64m1(Bcu, Aku, vl);
            Bcu = __riscv_vxor_vv_u64m1(Bcu, Amu, vl);
            Bcu = __riscv_vxor_vv_u64m1(Bcu, Asu, vl);

            // /* thetaRhoPiChiIotaPrepareTheta(round, A, E) */
            // Da = BCu ^ ROL64(BCe, 1);
            Da = __riscv_vrol_vx_u64m1(Bcu, 1, vl);
            Da = __riscv_vxor_vv_u64m1(Da, Bce, vl);
            // De = BCa ^ ROL64(BCi, 1);
            De = __riscv_vrol_vx_u64m1(Bca, 1, vl);
            De = __riscv_vxor_vv_u64m1(De, Bci, vl);
            // Di = BCe ^ ROL64(BCo, 1);
            Di = __riscv_vrol_vx_u64m1(Bce, 1, vl);
            Di = __riscv_vxor_vv_u64m1(Di, Bco, vl);
            // Do = BCi ^ ROL64(BCu, 1);
            Do = __riscv_vrol_vx_u64m1(Bci, 1, vl);
            Do = __riscv_vxor_vv_u64m1(Do, Bcu, vl);
            // Du = BCo ^ ROL64(BCa, 1);
            Du = __riscv_vrol_vx_u64m1(Bco, 1, vl);
            Du = __riscv_vxor_vv_u64m1(Du, Bca, vl);

            // Aba ^= Da;
            Aba = __riscv_vxor_vv_u64m1(Aba, Da, vl);
            // BCa = Aba;
            Bca = Aba;
            // Age ^= De;
            Age = __riscv_vxor_vv_u64m1(Age, De, vl);
            // BCe = ROL64(Age, 44);
            Bce = __riscv_vrol_vx_u64m1(Age, 44, vl);
            // Aki ^= Di;
            Aki = __riscv_vxor_vv_u64m1(Aki, Di, vl);
            // BCi = ROL64(Aki, 43);
            Bci = __riscv_vrol_vx_u64m1(Aki, 43, vl);
            // Amo ^= Do;
            Amo = __riscv_vxor_vv_u64m1(Amo, Do, vl);
            // BCo = ROL64(Amo, 21);
            Bco = __riscv_vrol_vx_u64m1(Amo, 21, vl);
            // Asu ^= Du;
            Asu = __riscv_vxor_vv_u64m1(Asu, Du, vl);
            // BCu = ROL64(Asu, 14);
            Bcu = __riscv_vrol_vx_u64m1(Asu, 14, vl);
            // Eba = BCa ^ ((~BCe) & BCi);
            Eba = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCe, vl), BCi, vl);
            Eba = __riscv_vxor_vv_u64m1(Eba, BCa, vl);
            // Eba ^= KeccakF_RoundConstants[round];
            Eba = __riscv_vadd_vx_u64m1(Eba, KeccakF_RoundConstants[round], vl);
            // Ebe = BCe ^ ((~BCi) & BCo);
            Ebe = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCi, vl), BCo, vl);
            Ebe = __riscv_vxor_vv_u64m1(Ebe, BCe, vl);
            // Ebi = BCi ^ ((~BCo) & BCu);
            Ebi = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCo, vl), BCu, vl);
            Ebi = __riscv_vxor_vv_u64m1(Ebi, BCi, vl);
            // Ebo = BCo ^ ((~BCu) & BCa);
            Ebo = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCu, vl), BCa, vl);
            Ebo = __riscv_vxor_vv_u64m1(Ebo, BCo, vl);
            // Ebu = BCu ^ ((~BCa) & BCe);
            Ebu = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCa, vl), BCe, vl);
            Ebu = __riscv_vxor_vv_u64m1(Ebu, BCu, vl);

            // Abo ^= Do;
            Abo = __riscv_vxor_vv_u64m1(Abo, Do, vl);
            // BCa = ROL64(Abo, 28);
            Bca = __riscv_vrol_vx_u64m1(Abo, 28, vl);
            // Agu ^= Du;
            Agu = __riscv_vxor_vv_u64m1(Agu, Du, vl);
            // BCe = ROL64(Agu, 20);
            Bce = __riscv_vrol_vx_u64m1(Agu, 20, vl);
            // Aka ^= Da;
            Aka = __riscv_vxor_vv_u64m1(Aka, Da, vl);
            // BCi = ROL64(Aka, 3);
            Bci = __riscv_vrol_vx_u64m1(Aka, 3, vl);
            // Ame ^= De;
            Ame = __riscv_vxor_vv_u64m1(Ame, De, vl);
            // BCo = ROL64(Ame, 45);
            Bco = __riscv_vrol_vx_u64m1(Ame, 45, vl);
            // Asi ^= Di;
            Asi = __riscv_vxor_vv_u64m1(Asi, Di, vl);
            // BCu = ROL64(Asi, 61);
            Bcu = __riscv_vrol_vx_u64m1(Asi, 61, vl);
            // Ega = BCa ^ ((~BCe) & BCi);
            Ega = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCe, vl), BCi, vl);
            Ega = __riscv_vxor_vv_u64m1(Ega, BCa, vl);
            // Ege = BCe ^ ((~BCi) & BCo);
            Ege = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCi, vl), BCo, vl);
            Ege = __riscv_vxor_vv_u64m1(Ege, BCe, vl);
            // Egi = BCi ^ ((~BCo) & BCu);
            Egi = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCo, vl), BCu, vl);
            Egi = __riscv_vxor_vv_u64m1(Egi, BCi, vl);
            // Ego = BCo ^ ((~BCu) & BCa);
            Ego = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCu, vl), BCa, vl);
            Ego = __riscv_vxor_vv_u64m1(Ego, BCo, vl);
            // Egu = BCu ^ ((~BCa) & BCe);
            Egu = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCa, vl), BCe, vl);
            Egu = __riscv_vxor_vv_u64m1(Egu, BCu, vl);

            // Abe ^= De;
            Abe = __riscv_vxor_vv_u64m1(Abe, De, vl);
            // BCa = ROL64(Abe, 1);
            Bca = __riscv_vrol_vx_u64m1(Abe, 1, vl);
            // Agi ^= Di;
            Agi = __riscv_vxor_vv_u64m1(Agi, Di, vl);
            // BCe = ROL64(Agi, 6);
            Bce = __riscv_vrol_vx_u64m1(Agi, 6, vl);
            // Ako ^= Do;
            Ako = __riscv_vxor_vv_u64m1(Ako, Do, vl);
            // BCi = ROL64(Ako, 25);
            Bci = __riscv_vrol_vx_u64m1(Ako, 25, vl);
            // Amu ^= Du;
            Amu = __riscv_vxor_vv_u64m1(Amu, Du, vl);
            // BCo = ROL64(Amu, 8);
            Bco = __riscv_vrol_vx_u64m1(Amu, 8, vl);
            // Asa ^= Da;
            Asa = __riscv_vxor_vv_u64m1(Asa, Da, vl);
            // BCu = ROL64(Asa, 18);
            Bcu = __riscv_vrol_vx_u64m1(Asa, 18, vl);
            // Eka = BCa ^ ((~BCe) & BCi);
            Eka = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCe, vl), BCi, vl);
            Eka = __riscv_vxor_vv_u64m1(Eka, BCa, vl);
            // Eke = BCe ^ ((~BCi) & BCo);
            Eke = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCi, vl), BCo, vl);
            Eke = __riscv_vxor_vv_u64m1(Eke, BCe, vl);
            // Eki = BCi ^ ((~BCo) & BCu);
            Eki = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCo, vl), BCu, vl);
            Eki = __riscv_vxor_vv_u64m1(Eki, BCi, vl);
            // Eko = BCo ^ ((~BCu) & BCa);
            Eko = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCu, vl), BCa, vl);
            Eko = __riscv_vxor_vv_u64m1(Eko, BCo, vl);
            // Eku = BCu ^ ((~BCa) & BCe);
            Eku = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCa, vl), BCe, vl);
            Eku = __riscv_vxor_vv_u64m1(Eku, BCu, vl);

            // Abu ^= Du;
            Abu = __riscv_vxor_vv_u64m1(Abu, Du, vl);
            // BCa = ROL64(Abu, 27);
            Bca = __riscv_vrol_vx_u64m1(Abu, 27, vl);
            // Aga ^= Da;
            Aga = __riscv_vxor_vv_u64m1(Aga, Da, vl);
            // BCe = ROL64(Aga, 36);
            Bce = __riscv_vrol_vx_u64m1(Aga, 36, vl);
            // Ake ^= De;
            Ake = __riscv_vxor_vv_u64m1(Ake, De, vl);
            // BCi = ROL64(Ake, 10);
            Bci = __riscv_vrol_vx_u64m1(Ake, 10, vl);
            // Ami ^= Di;
            Ami = __riscv_vxor_vv_u64m1(Ami, Di, vl);
            // BCo = ROL64(Ami, 15);
            Bco = __riscv_vrol_vx_u64m1(Ami, 15, vl);
            // Aso ^= Do;
            Aso = __riscv_vxor_vv_u64m1(Aso, Do, vl);
            // BCu = ROL64(Aso, 56);
            Bcu = __riscv_vrol_vx_u64m1(Aso, 56, vl);
            // Ema = BCa ^ ((~BCe) & BCi);
            Ema = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCe, vl), BCi, vl);
            Ema = __riscv_vxor_vv_u64m1(Ema, BCa, vl);
            // Eme = BCe ^ ((~BCi) & BCo);
            Eme = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCi, vl), BCo, vl);
            Eme = __riscv_vxor_vv_u64m1(Eme, BCe, vl);
            // Emi = BCi ^ ((~BCo) & BCu);
            Emi = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCo, vl), BCu, vl);
            Emi = __riscv_vxor_vv_u64m1(Emi, BCi, vl);
            // Emo = BCo ^ ((~BCu) & BCa);
            Emo = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCu, vl), BCa, vl);
            Emo = __riscv_vxor_vv_u64m1(Emo, BCo, vl);
            // Emu = BCu ^ ((~BCa) & BCe);
            Emu = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCa, vl), BCe, vl);
            Emu = __riscv_vxor_vv_u64m1(Emu, BCu, vl);

            // Abi ^= Di;
            Abi = __riscv_vxor_vv_u64m1(Abi, Di, vl);
            // BCa = ROL64(Abi, 62);
            Bca = __riscv_vrol_vx_u64m1(Abi, 62, vl);
            // Ago ^= Do;
            Ago = __riscv_vxor_vv_u64m1(Ago, Do, vl);
            // BCe = ROL64(Ago, 55);
            Bce = __riscv_vrol_vx_u64m1(Ago, 55, vl);
            // Aku ^= Du;
            Aku = __riscv_vxor_vv_u64m1(Aku, Du, vl);
            // BCi = ROL64(Aku, 39);
            Bci = __riscv_vrol_vx_u64m1(Aku, 39, vl);
            // Ama ^= Da;
            Ama = __riscv_vxor_vv_u64m1(Ama, Da, vl);
            // BCo = ROL64(Ama, 41);
            Bco = __riscv_vrol_vx_u64m1(Ama, 41, vl);
            // Ase ^= De;
            Ase = __riscv_vxor_vv_u64m1(Ase, De, vl);
            // BCu = ROL64(Ase, 2);
            Bcu = __riscv_vrol_vx_u64m1(Ase, 2, vl);
            // Esa = BCa ^ ((~BCe) & BCi);
            Esa = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCe, vl), BCi, vl);
            Esa = __riscv_vxor_vv_u64m1(Esa, BCa, vl);
            // Ese = BCe ^ ((~BCi) & BCo);
            Ese = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCi, vl), BCo, vl);
            Ese = __riscv_vxor_vv_u64m1(Ese, BCe, vl);
            // Esi = BCi ^ ((~BCo) & BCu);
            Esi = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCo, vl), BCu, vl);
            Esi = __riscv_vxor_vv_u64m1(Esi, BCi, vl);
            // Eso = BCo ^ ((~BCu) & BCa);
            Eso = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCu, vl), BCa, vl);
            Eso = __riscv_vxor_vv_u64m1(Eso, BCo, vl);
            // Esu = BCu ^ ((~BCa) & BCe);
            Esu = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCa, vl), BCe, vl);
            Esu = __riscv_vxor_vv_u64m1(Esu, BCu, vl);

            // /* prepareTheta */
            // BCa = Eba ^ Ega ^ Eka ^ Ema ^ Esa;
            Bca = __riscv_vxor_vv_u64m1(Eba, Ega, vl);
            Bca = __riscv_vxor_vv_u64m1(Bca, Eka, vl);
            Bca = __riscv_vxor_vv_u64m1(Bca, Ema, vl);
            Bca = __riscv_vxor_vv_u64m1(Bca, Esa, vl);
            // BCe = Ebe ^ Ege ^ Eke ^ Eme ^ Ese;
            Bce = __riscv_vxor_vv_u64m1(Ebe, Ege, vl);
            Bce = __riscv_vxor_vv_u64m1(Bce, Eke, vl);
            Bce = __riscv_vxor_vv_u64m1(Bce, Eme, vl);
            Bce = __riscv_vxor_vv_u64m1(Bce, Ese, vl);
            // BCi = Ebi ^ Egi ^ Eki ^ Emi ^ Esi;
            Bci = __riscv_vxor_vv_u64m1(Ebi, Egi, vl);
            Bci = __riscv_vxor_vv_u64m1(Bci, Eki, vl);
            Bci = __riscv_vxor_vv_u64m1(Bci, Emi, vl);
            Bci = __riscv_vxor_vv_u64m1(Bci, Esi, vl);
            // BCo = Ebo ^ Ego ^ Eko ^ Emo ^ Eso;
            Bco = __riscv_vxor_vv_u64m1(Ebo, Ego, vl);
            Bco = __riscv_vxor_vv_u64m1(Bco, Eko, vl);
            Bco = __riscv_vxor_vv_u64m1(Bco, Emo, vl);
            Bco = __riscv_vxor_vv_u64m1(Bco, Eso, vl);
            // BCu = Ebu ^ Egu ^ Eku ^ Emu ^ Esu;
            Bcu = __riscv_vxor_vv_u64m1(Ebu, Egu, vl);
            Bcu = __riscv_vxor_vv_u64m1(Bcu, Eku, vl);
            Bcu = __riscv_vxor_vv_u64m1(Bcu, Emu, vl);
            Bcu = __riscv_vxor_vv_u64m1(Bcu, Esu, vl);

            // /* thetaRhoPiChiIotaPrepareTheta(round+1, E, A) */
            // Da = BCu ^ ROL64(BCe, 1);
            Da = __riscv_vrol_vx_u64m1(BCe, 1, vl);
            Da = __riscv_vxor_vv_u64m1(Da, BCu, vl);
            // De = BCa ^ ROL64(BCi, 1);
            De = __riscv_vrol_vx_u64m1(BCi, 1, vl);
            De = __riscv_vxor_vv_u64m1(De, BCa, vl);
            // Di = BCe ^ ROL64(BCo, 1);
            Di = __riscv_vrol_vx_u64m1(BCo, 1, vl);
            Di = __riscv_vxor_vv_u64m1(Di, BCe, vl);
            // Do = BCi ^ ROL64(BCu, 1);
            Do = __riscv_vrol_vx_u64m1(BCu, 1, vl);
            Do = __riscv_vxor_vv_u64m1(Do, BCi, vl);
            // Du = BCo ^ ROL64(BCa, 1);
            Du = __riscv_vrol_vx_u64m1(BCa, 1, vl);
            Du = __riscv_vxor_vv_u64m1(Du, BCo, vl);

            // Eba ^= Da;
            Eba = __riscv_vxor_vv_u64m1(Eba, Da, vl);
            // BCa = Eba;
            Bca = Eba;
            // Ege ^= De;
            Ege = __riscv_vxor_vv_u64m1(Ege, De, vl);
            // BCe = ROL64(Ege, 44);
            Bce = __riscv_vrol_vx_u64m1(Ege, 44, vl);
            // Eki ^= Di;
            Eki = __riscv_vxor_vv_u64m1(Eki, Di, vl);
            // BCi = ROL64(Eki, 43);
            Bci = __riscv_vrol_vx_u64m1(Eki, 43, vl);
            // Emo ^= Do;
            Emo = __riscv_vxor_vv_u64m1(Emo, Do, vl);
            // BCo = ROL64(Emo, 21);
            Bco = __riscv_vrol_vx_u64m1(Emo, 21, vl);
            // Esu ^= Du;
            Esu = __riscv_vxor_vv_u64m1(Esu, Du, vl);
            // BCu = ROL64(Esu, 14);
            Bcu = __riscv_vrol_vx_u64m1(Esu, 14, vl);
            // Aba = BCa ^ ((~BCe) & BCi);
            Aba = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCe), BCi, vl);
            Aba = __riscv_vxor_vv_u64m1(Aba, BCa, vl);
            // Aba ^= KeccakF_RoundConstants[round + 1];
            Aba = __riscv_vxor_vx_u64m1_tu(Aba, Aba, KeccakF_RoundConstants[round + 1], 1);
            // Abe = BCe ^ ((~BCi) & BCo);
            Abe = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCi), BCo, vl);
            Abe = __riscv_vxor_vv_u64m1(Abe, BCe, vl);
            // Abi = BCi ^ ((~BCo) & BCu);
            Abi = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCo), BCu, vl);
            Abi = __riscv_vxor_vv_u64m1(Abi, BCi, vl);
            // Abo = BCo ^ ((~BCu) & BCa);
            Abo = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCu), BCa, vl);
            Abo = __riscv_vxor_vv_u64m1(Abo, BCo, vl);
            // Abu = BCu ^ ((~BCa) & BCe);
            Abu = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCa), BCe, vl);
            Abu = __riscv_vxor_vv_u64m1(Abu, BCu, vl);
            

            // Ebo ^= Do;
            Ebo = __riscv_vxor_vv_u64m1(Ebo, Do, vl);
            // BCa = ROL64(Ebo, 28);
            Bca = __riscv_vrol_vx_u64m1(Ebo, 28, vl);
            // Egu ^= Du;
            Egu = __riscv_vxor_vv_u64m1(Egu, Du, vl);
            // BCe = ROL64(Egu, 20);
            Bce = __riscv_vrol_vx_u64m1(Egu, 20, vl);
            // Eka ^= Da;
            Eka = __riscv_vxor_vv_u64m1(Eka, Da, vl);
            // BCi = ROL64(Eka, 3);
            Bci = __riscv_vrol_vx_u64m1(Eka, 3, vl);
            // Eme ^= De;
            Eme = __riscv_vxor_vv_u64m1(Eme, De, vl);
            // BCo = ROL64(Eme, 45);
            Bco = __riscv_vrol_vx_u64m1(Eme, 45, vl);
            // Esi ^= Di;
            Esi = __riscv_vxor_vv_u64m1(Esi, Di, vl);
            // BCu = ROL64(Esi, 61);
            Bcu = __riscv_vrol_vx_u64m1(Esi, 61, vl);
            // Aga = BCa ^ ((~BCe) & BCi);
            Aga = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCe), BCi, vl);
            Aga = __riscv_vxor_vv_u64m1(Aga, BCa, vl);
            // Age = BCe ^ ((~BCi) & BCo);
            Age = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCi), BCo, vl);
            Age = __riscv_vxor_vv_u64m1(Age, BCe, vl);
            // Agi = BCi ^ ((~BCo) & BCu);
            Agi = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCo), BCu, vl);
            Agi = __riscv_vxor_vv_u64m1(Agi, BCi, vl);
            // Ago = BCo ^ ((~BCu) & BCa);
            Ago = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCu), BCa, vl);
            Ago = __riscv_vxor_vv_u64m1(Ago, BCo, vl);
            // Agu = BCu ^ ((~BCa) & BCe);
            Agu = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCa), BCe, vl);
            Agu = __riscv_vxor_vv_u64m1(Agu, BCu, vl);

            // Ebe ^= De;
            Ebe = __riscv_vxor_vv_u64m1(Ebe, De, vl);
            // BCa = ROL64(Ebe, 1);
            Bca = __riscv_vrol_vx_u64m1(Ebe, 1, vl);
            // Egi ^= Di;
            Egi = __riscv_vxor_vv_u64m1(Egi, Di, vl);
            // BCe = ROL64(Egi, 6);
            Bce = __riscv_vrol_vx_u64m1(Egi, 6, vl);
            // Eko ^= Do;
            Eko = __riscv_vxor_vv_u64m1(Eko, Do, vl);
            // BCi = ROL64(Eko, 25);
            Bci = __riscv_vrol_vx_u64m1(Eko, 25, vl);
            // Emu ^= Du;
            Emu = __riscv_vxor_vv_u64m1(Emu, Du, vl);
            // BCo = ROL64(Emu, 8);
            Bco = __riscv_vrol_vx_u64m1(Emu, 8, vl);
            // Esa ^= Da;
            Esa = __riscv_vxor_vv_u64m1(Esa, Da, vl);
            // BCu = ROL64(Esa, 18);
            Bcu = __riscv_vrol_vx_u64m1(Esa, 18, vl);
            // Aka = BCa ^ ((~BCe) & BCi);
            Aka = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCe), BCi, vl);
            Aka = __riscv_vxor_vv_u64m1(Aka, BCa, vl);
            // Ake = BCe ^ ((~BCi) & BCo);
            Ake = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCi), BCo, vl);
            Ake = __riscv_vxor_vv_u64m1(Ake, BCe, vl);
            // Aki = BCi ^ ((~BCo) & BCu);
            Aki = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCo), BCu, vl);
            Aki = __riscv_vxor_vv_u64m1(Aki, BCi, vl);
            // Ako = BCo ^ ((~BCu) & BCa);
            Ako = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCu), BCa, vl);
            Ako = __riscv_vxor_vv_u64m1(Ako, BCo, vl);
            // Aku = BCu ^ ((~BCa) & BCe);
            Aku = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCa), BCe, vl);
            Aku = __riscv_vxor_vv_u64m1(Aku, BCu, vl);

            // Ebu ^= Du;
            Ebu = __riscv_vxor_vv_u64m1(Ebu, Du, vl);
            // BCa = ROL64(Ebu, 27);
            Bca = __riscv_vrol_vx_u64m1(Ebu, 27, vl);
            // Ega ^= Da;
            Ega = __riscv_vxor_vv_u64m1(Ega, Da, vl);
            // BCe = ROL64(Ega, 36);
            Bce = __riscv_vrol_vx_u64m1(Ega, 36, vl);
            // Eke ^= De;
            Eke = __riscv_vxor_vv_u64m1(Eke, De, vl);
            // BCi = ROL64(Eke, 10);
            Bci = __riscv_vrol_vx_u64m1(Eke, 10, vl);
            // Emi ^= Di;
            Emi = __riscv_vxor_vv_u64m1(Emi, Di, vl);
            // BCo = ROL64(Emi, 15);
            Bco = __riscv_vrol_vx_u64m1(Emi, 15, vl);
            // Eso ^= Do;
            Eso = __riscv_vxor_vv_u64m1(Eso, Do, vl);
            // BCu = ROL64(Eso, 56);
            Bcu = __riscv_vrol_vx_u64m1(Eso, 56, vl);
            // Ama = BCa ^ ((~BCe) & BCi);
            Ama = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCe), BCi, vl);
            Ama = __riscv_vxor_vv_u64m1(Ama, BCa, vl);
            // Ame = BCe ^ ((~BCi) & BCo);
            Ame = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCi), BCo, vl);
            Ame = __riscv_vxor_vv_u64m1(Ame, BCe, vl);
            // Ami = BCi ^ ((~BCo) & BCu);
            Ami = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCo), BCu, vl);
            Ami = __riscv_vxor_vv_u64m1(Ami, BCi, vl);
            // Amo = BCo ^ ((~BCu) & BCa);
            Amo = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCu), BCa, vl);
            Amo = __riscv_vxor_vv_u64m1(Amo, BCo, vl);
            // Amu = BCu ^ ((~BCa) & BCe);
            Amu = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCa), BCe, vl);
            Amu = __riscv_vxor_vv_u64m1(Amu, BCu, vl);

            // Ebi ^= Di;
            Ebi = __riscv_vxor_vv_u64m1(Ebi, Di, vl);
            // BCa = ROL64(Ebi, 62);
            Bca = __riscv_vrol_vx_u64m1(Ebi, 62, vl);
            // Ego ^= Do;
            Ego = __riscv_vxor_vv_u64m1(Ego, Do, vl);
            // BCe = ROL64(Ego, 55);
            Bce = __riscv_vrol_vx_u64m1(Ego, 55, vl);
            // Eku ^= Du;
            Eku = __riscv_vxor_vv_u64m1(Eku, Du, vl);
            // BCi = ROL64(Eku, 39);
            Bci = __riscv_vrol_vx_u64m1(Eku, 39, vl);
            // Ema ^= Da;
            Ema = __riscv_vxor_vv_u64m1(Ema, Da, vl);
            // BCo = ROL64(Ema, 41);
            Bco = __riscv_vrol_vx_u64m1(Ema, 41, vl);
            // Ese ^= De;
            Ese = __riscv_vxor_vv_u64m1(Ese, De, vl);
            // BCu = ROL64(Ese, 2);
            Bcu = __riscv_vrol_vx_u64m1(Ese, 2, vl);
            // Asa = BCa ^ ((~BCe) & BCi);
            Asa = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCe), BCi, vl);
            Asa = __riscv_vxor_vv_u64m1(Asa, BCa, vl);
            // Ase = BCe ^ ((~BCi) & BCo);
            Ase = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCi), BCo, vl);
            Ase = __riscv_vxor_vv_u64m1(Ase, BCe, vl);
            // Asi = BCi ^ ((~BCo) & BCu);
            Asi = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCo), BCu, vl);
            Asi = __riscv_vxor_vv_u64m1(Asi, BCi, vl);
            // Aso = BCo ^ ((~BCu) & BCa);
            Aso = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCu), BCa, vl);
            Aso = __riscv_vxor_vv_u64m1(Aso, BCo, vl);
            // Asu = BCu ^ ((~BCa) & BCe);
            Asu = __riscv_vand_vv_u64m1(__riscv_vnot_v_u64m1(BCa), BCe, vl);
            Asu = __riscv_vxor_vv_u64m1(Asu, BCu, vl);
        }

        // Store result states back using strided store
        // state[0] = Aba;
        __riscv_vsse64_v_u64m1(&state[0], stride, Aba, vl);
        // state[1] = Abe;
        __riscv_vsse64_v_u64m1(&state[1], stride, Abe, vl);
        // state[2] = Abi;
        __riscv_vsse64_v_u64m1(&state[2], stride, Abi, vl);
        // state[3] = Abo;
        __riscv_vsse64_v_u64m1(&state[3], stride, Abo, vl);
        // state[4] = Abu;
        __riscv_vsse64_v_u64m1(&state[4], stride, Abu, vl);
        // state[5] = Aga;
        __riscv_vsse64_v_u64m1(&state[5], stride, Aga, vl);
        // state[6] = Age;
        __riscv_vsse64_v_u64m1(&state[6], stride, Age, vl);
        // state[7] = Agi;
        __riscv_vsse64_v_u64m1(&state[7], stride, Agi, vl);
        // state[8] = Ago;
        __riscv_vsse64_v_u64m1(&state[8], stride, Ago, vl);
        // state[9] = Agu;
        __riscv_vsse64_v_u64m1(&state[9], stride, Agu, vl);
        // state[10] = Aka;
        __riscv_vsse64_v_u64m1(&state[10], stride, Aka, vl);
        // state[11] = Ake;
        __riscv_vsse64_v_u64m1(&state[11], stride, Ake, vl);
        // state[12] = Aki;
        __riscv_vsse64_v_u64m1(&state[12], stride, Aki, vl);
        // state[13] = Ako;
        __riscv_vsse64_v_u64m1(&state[13], stride, Ako, vl);
        // state[14] = Aku;
        __riscv_vsse64_v_u64m1(&state[14], stride, Aku, vl);
        // state[15] = Ama;
        __riscv_vsse64_v_u64m1(&state[15], stride, Ama, vl);
        // state[16] = Ame;
        __riscv_vsse64_v_u64m1(&state[16], stride, Ame, vl);
        // state[17] = Ami;
        __riscv_vsse64_v_u64m1(&state[17], stride, Ami, vl);
        // state[18] = Amo;
        __riscv_vsse64_v_u64m1(&state[18], stride, Amo, vl);
        // state[19] = Amu;
        __riscv_vsse64_v_u64m1(&state[19], stride, Amu, vl);
        // state[20] = Asa;
        __riscv_vsse64_v_u64m1(&state[20], stride, Asa, vl);
        // state[21] = Ase;
        __riscv_vsse64_v_u64m1(&state[21], stride, Ase, vl);
        // state[22] = Asi;
        __riscv_vsse64_v_u64m1(&state[22], stride, Asi, vl);
        // state[23] = Aso;
        __riscv_vsse64_v_u64m1(&state[23], stride, Aso, vl);
        // state[24] = Asu;
        __riscv_vsse64_v_u64m1(&state[24], stride, Asu, vl);


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
