/* Copyright (c) 2022 Arm Limited
 * Copyright (c) 2022 Hanno Becker
 * Copyright (c) 2023 Amin Abdulrahman, Matthias Kannwischer
 * Copyright (c) The mldsa-native project authors
 * SPDX-License-Identifier: MIT
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "../../../common.h"
#if defined(MLD_ARITH_BACKEND_AARCH64)

/*
 * WARNING: This file is auto-derived from the mldsa-native source file
 *   dev/aarch64_clean/src/ntt.S using scripts/simpasm. Do not modify it directly.
 */


.text
.balign 4
.global MLD_ASM_NAMESPACE(ntt_asm)
MLD_ASM_FN_SYMBOL(ntt_asm)

        sub	sp, sp, #0x40
        stp	d8, d9, [sp]
        stp	d10, d11, [sp, #0x10]
        stp	d12, d13, [sp, #0x20]
        stp	d14, d15, [sp, #0x30]
        mov	w6, #0xe001             // =57345
        movk	w6, #0x7f, lsl #16
        dup	v8.4s, w6
        mov	x4, x0
        mov	x3, #0x8                // =8
        ldr	q0, [x1], #0x40
        ldur	q1, [x1, #-0x30]
        ldur	q2, [x1, #-0x20]
        ldur	q3, [x1, #-0x10]

layer123_start:
        ldr	q9, [x0]
        ldr	q10, [x0, #0x80]
        ldr	q11, [x0, #0x100]
        ldr	q12, [x0, #0x180]
        ldr	q13, [x0, #0x200]
        ldr	q14, [x0, #0x280]
        ldr	q15, [x0, #0x300]
        ldr	q16, [x0, #0x380]
        sqrdmulh	v27.4s, v13.4s, v0.s[1]
        mul	v24.4s, v13.4s, v0.s[0]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v13.4s, v9.4s, v24.4s
        add	v9.4s, v9.4s, v24.4s
        sqrdmulh	v27.4s, v14.4s, v0.s[1]
        mul	v24.4s, v14.4s, v0.s[0]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v14.4s, v10.4s, v24.4s
        add	v10.4s, v10.4s, v24.4s
        sqrdmulh	v27.4s, v15.4s, v0.s[1]
        mul	v24.4s, v15.4s, v0.s[0]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v15.4s, v11.4s, v24.4s
        add	v11.4s, v11.4s, v24.4s
        sqrdmulh	v27.4s, v16.4s, v0.s[1]
        mul	v24.4s, v16.4s, v0.s[0]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v16.4s, v12.4s, v24.4s
        add	v12.4s, v12.4s, v24.4s
        sqrdmulh	v27.4s, v11.4s, v0.s[3]
        mul	v24.4s, v11.4s, v0.s[2]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v11.4s, v9.4s, v24.4s
        add	v9.4s, v9.4s, v24.4s
        sqrdmulh	v27.4s, v12.4s, v0.s[3]
        mul	v24.4s, v12.4s, v0.s[2]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v12.4s, v10.4s, v24.4s
        add	v10.4s, v10.4s, v24.4s
        sqrdmulh	v27.4s, v15.4s, v1.s[1]
        mul	v24.4s, v15.4s, v1.s[0]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v15.4s, v13.4s, v24.4s
        add	v13.4s, v13.4s, v24.4s
        sqrdmulh	v27.4s, v16.4s, v1.s[1]
        mul	v24.4s, v16.4s, v1.s[0]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v16.4s, v14.4s, v24.4s
        add	v14.4s, v14.4s, v24.4s
        sqrdmulh	v27.4s, v10.4s, v1.s[3]
        mul	v24.4s, v10.4s, v1.s[2]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v10.4s, v9.4s, v24.4s
        add	v9.4s, v9.4s, v24.4s
        sqrdmulh	v27.4s, v12.4s, v2.s[1]
        mul	v24.4s, v12.4s, v2.s[0]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v12.4s, v11.4s, v24.4s
        add	v11.4s, v11.4s, v24.4s
        sqrdmulh	v27.4s, v14.4s, v2.s[3]
        mul	v24.4s, v14.4s, v2.s[2]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v14.4s, v13.4s, v24.4s
        add	v13.4s, v13.4s, v24.4s
        sqrdmulh	v27.4s, v16.4s, v3.s[1]
        mul	v24.4s, v16.4s, v3.s[0]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v16.4s, v15.4s, v24.4s
        add	v15.4s, v15.4s, v24.4s
        str	q9, [x0], #0x10
        str	q10, [x0, #0x70]
        str	q11, [x0, #0xf0]
        str	q12, [x0, #0x170]
        str	q13, [x0, #0x1f0]
        str	q14, [x0, #0x270]
        str	q15, [x0, #0x2f0]
        str	q16, [x0, #0x370]
        subs	x3, x3, #0x1
        cbnz	x3, layer123_start
        mov	x0, x4
        add	x5, x0, #0x40
        mov	x3, #0x8                // =8
        sub	x0, x0, #0x40
        sub	x5, x5, #0x40

layer45678_start:
        ldr	q9, [x0, #0x40]
        ldr	q10, [x0, #0x50]
        ldr	q11, [x0, #0x60]
        ldr	q12, [x0, #0x70]
        ldr	q13, [x5, #0x40]
        ldr	q14, [x5, #0x50]
        ldr	q15, [x5, #0x60]
        ldr	q16, [x5, #0x70]
        add	x0, x0, #0x40
        add	x5, x5, #0x40
        ldr	q0, [x1], #0x40
        ldur	q1, [x1, #-0x30]
        ldur	q2, [x1, #-0x20]
        ldur	q3, [x1, #-0x10]
        sqrdmulh	v27.4s, v13.4s, v0.s[1]
        mul	v24.4s, v13.4s, v0.s[0]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v13.4s, v9.4s, v24.4s
        add	v9.4s, v9.4s, v24.4s
        sqrdmulh	v27.4s, v14.4s, v0.s[1]
        mul	v24.4s, v14.4s, v0.s[0]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v14.4s, v10.4s, v24.4s
        add	v10.4s, v10.4s, v24.4s
        sqrdmulh	v27.4s, v15.4s, v0.s[1]
        mul	v24.4s, v15.4s, v0.s[0]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v15.4s, v11.4s, v24.4s
        add	v11.4s, v11.4s, v24.4s
        sqrdmulh	v27.4s, v16.4s, v0.s[1]
        mul	v24.4s, v16.4s, v0.s[0]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v16.4s, v12.4s, v24.4s
        add	v12.4s, v12.4s, v24.4s
        sqrdmulh	v27.4s, v11.4s, v0.s[3]
        mul	v24.4s, v11.4s, v0.s[2]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v11.4s, v9.4s, v24.4s
        add	v9.4s, v9.4s, v24.4s
        sqrdmulh	v27.4s, v12.4s, v0.s[3]
        mul	v24.4s, v12.4s, v0.s[2]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v12.4s, v10.4s, v24.4s
        add	v10.4s, v10.4s, v24.4s
        sqrdmulh	v27.4s, v15.4s, v1.s[1]
        mul	v24.4s, v15.4s, v1.s[0]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v15.4s, v13.4s, v24.4s
        add	v13.4s, v13.4s, v24.4s
        sqrdmulh	v27.4s, v16.4s, v1.s[1]
        mul	v24.4s, v16.4s, v1.s[0]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v16.4s, v14.4s, v24.4s
        add	v14.4s, v14.4s, v24.4s
        sqrdmulh	v27.4s, v10.4s, v1.s[3]
        mul	v24.4s, v10.4s, v1.s[2]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v10.4s, v9.4s, v24.4s
        add	v9.4s, v9.4s, v24.4s
        sqrdmulh	v27.4s, v12.4s, v2.s[1]
        mul	v24.4s, v12.4s, v2.s[0]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v12.4s, v11.4s, v24.4s
        add	v11.4s, v11.4s, v24.4s
        sqrdmulh	v27.4s, v14.4s, v2.s[3]
        mul	v24.4s, v14.4s, v2.s[2]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v14.4s, v13.4s, v24.4s
        add	v13.4s, v13.4s, v24.4s
        sqrdmulh	v27.4s, v16.4s, v3.s[1]
        mul	v24.4s, v16.4s, v3.s[0]
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v16.4s, v15.4s, v24.4s
        add	v15.4s, v15.4s, v24.4s
        trn1	v25.4s, v9.4s, v10.4s
        trn2	v26.4s, v9.4s, v10.4s
        trn1	v27.4s, v11.4s, v12.4s
        trn2	v28.4s, v11.4s, v12.4s
        trn2	v11.2d, v25.2d, v27.2d
        trn2	v12.2d, v26.2d, v28.2d
        trn1	v9.2d, v25.2d, v27.2d
        trn1	v10.2d, v26.2d, v28.2d
        trn1	v25.4s, v13.4s, v14.4s
        trn2	v26.4s, v13.4s, v14.4s
        trn1	v27.4s, v15.4s, v16.4s
        trn2	v28.4s, v15.4s, v16.4s
        trn2	v15.2d, v25.2d, v27.2d
        trn2	v16.2d, v26.2d, v28.2d
        trn1	v13.2d, v25.2d, v27.2d
        trn1	v14.2d, v26.2d, v28.2d
        ldr	q0, [x2], #0xc0
        ldur	q4, [x2, #-0xb0]
        ldur	q1, [x2, #-0xa0]
        ldur	q5, [x2, #-0x90]
        ldur	q2, [x2, #-0x80]
        ldur	q6, [x2, #-0x70]
        sqrdmulh	v27.4s, v11.4s, v4.4s
        mul	v24.4s, v11.4s, v0.4s
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v11.4s, v9.4s, v24.4s
        add	v9.4s, v9.4s, v24.4s
        sqrdmulh	v27.4s, v12.4s, v4.4s
        mul	v24.4s, v12.4s, v0.4s
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v12.4s, v10.4s, v24.4s
        add	v10.4s, v10.4s, v24.4s
        sqrdmulh	v27.4s, v10.4s, v5.4s
        mul	v24.4s, v10.4s, v1.4s
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v10.4s, v9.4s, v24.4s
        add	v9.4s, v9.4s, v24.4s
        sqrdmulh	v27.4s, v12.4s, v6.4s
        mul	v24.4s, v12.4s, v2.4s
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v12.4s, v11.4s, v24.4s
        add	v11.4s, v11.4s, v24.4s
        ldur	q0, [x2, #-0x60]
        ldur	q4, [x2, #-0x50]
        ldur	q1, [x2, #-0x40]
        ldur	q5, [x2, #-0x30]
        ldur	q2, [x2, #-0x20]
        ldur	q6, [x2, #-0x10]
        sqrdmulh	v27.4s, v15.4s, v4.4s
        mul	v24.4s, v15.4s, v0.4s
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v15.4s, v13.4s, v24.4s
        add	v13.4s, v13.4s, v24.4s
        sqrdmulh	v27.4s, v16.4s, v4.4s
        mul	v24.4s, v16.4s, v0.4s
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v16.4s, v14.4s, v24.4s
        add	v14.4s, v14.4s, v24.4s
        sqrdmulh	v27.4s, v14.4s, v5.4s
        mul	v24.4s, v14.4s, v1.4s
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v14.4s, v13.4s, v24.4s
        add	v13.4s, v13.4s, v24.4s
        sqrdmulh	v27.4s, v16.4s, v6.4s
        mul	v24.4s, v16.4s, v2.4s
        mls	v24.4s, v27.4s, v8.s[0]
        sub	v16.4s, v15.4s, v24.4s
        add	v15.4s, v15.4s, v24.4s
        st4	{ v9.4s, v10.4s, v11.4s, v12.4s }, [x0], #64
        st4	{ v13.4s, v14.4s, v15.4s, v16.4s }, [x5], #64
        subs	x3, x3, #0x1
        cbnz	x3, layer45678_start
        ldp	d8, d9, [sp]
        ldp	d10, d11, [sp, #0x10]
        ldp	d12, d13, [sp, #0x20]
        ldp	d14, d15, [sp, #0x30]
        add	sp, sp, #0x40
        ret

#endif /* MLD_ARITH_BACKEND_AARCH64 */
