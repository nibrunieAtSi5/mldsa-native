	.text
	.attribute	4, 16
	.attribute	5, "rv64i2p1_m2p0_a2p1_f2p2_d2p2_c2p0_v1p0_zicbom1p0_zicboz1p0_zicntr2p0_zicond1p0_zicsr2p0_zifencei2p0_zihintpause2p0_zihpm2p0_zfh1p0_zfhmin1p0_zca1p0_zcd1p0_zba1p0_zbb1p0_zbc1p0_zbs1p0_zkt1p0_zve32f1p0_zve32x1p0_zve64d1p0_zve64f1p0_zve64x1p0_zvl128b1p0_zvl32b1p0_zvl64b1p0"
	.file	"KeccakP-1600-rv64-x4-vector.c"
	.globl	KeccakP1600_StatePermute_x4_vector # -- Begin function KeccakP1600_StatePermute_x4_vector
	.p2align	1
	.type	KeccakP1600_StatePermute_x4_vector,@function
KeccakP1600_StatePermute_x4_vector:     # @KeccakP1600_StatePermute_x4_vector
	.cfi_startproc
# %bb.0:
	addi	sp, sp, -320
	.cfi_def_cfa_offset 320
	sd	ra, 312(sp)                     # 8-byte Folded Spill
	sd	s0, 304(sp)                     # 8-byte Folded Spill
	sd	s1, 296(sp)                     # 8-byte Folded Spill
	sd	s2, 288(sp)                     # 8-byte Folded Spill
	sd	s3, 280(sp)                     # 8-byte Folded Spill
	sd	s4, 272(sp)                     # 8-byte Folded Spill
	sd	s5, 264(sp)                     # 8-byte Folded Spill
	sd	s6, 256(sp)                     # 8-byte Folded Spill
	sd	s7, 248(sp)                     # 8-byte Folded Spill
	sd	s8, 240(sp)                     # 8-byte Folded Spill
	sd	s9, 232(sp)                     # 8-byte Folded Spill
	sd	s10, 224(sp)                    # 8-byte Folded Spill
	sd	s11, 216(sp)                    # 8-byte Folded Spill
	.cfi_offset ra, -8
	.cfi_offset s0, -16
	.cfi_offset s1, -24
	.cfi_offset s2, -32
	.cfi_offset s3, -40
	.cfi_offset s4, -48
	.cfi_offset s5, -56
	.cfi_offset s6, -64
	.cfi_offset s7, -72
	.cfi_offset s8, -80
	.cfi_offset s9, -88
	.cfi_offset s10, -96
	.cfi_offset s11, -104
	csrr	a1, vlenb
	slli	a1, a1, 2
	sub	sp, sp, a1
	.cfi_escape 0x0f, 0x0e, 0x72, 0x00, 0x11, 0xc0, 0x02, 0x22, 0x11, 0x04, 0x92, 0xa2, 0x38, 0x00, 0x1e, 0x22 # sp + 320 + 4 * vlenb
	li	a7, 4
	li	t0, 200
.Lpcrel_hi0:
	auipc	a1, %pcrel_hi(RC)
	addi	t1, a1, %pcrel_lo(.Lpcrel_hi0)
	addi	a1, t1, 8
	sd	a1, 24(sp)                      # 8-byte Folded Spill
	li	a5, 63
	li	t5, 44
	li	t6, 43
	li	t2, 50
	li	a3, 36
	li	a2, 61
	li	t3, 45
	li	t4, 58
	li	a4, 39
	li	a1, 56
	li	s2, 46
	li	s3, 37
	li	s4, 54
	li	s5, 49
	li	s0, 62
	li	s6, 55
	li	s7, 41
.LBB0_1:                                # =>This Loop Header: Depth=1
                                        #     Child Loop BB0_2 Depth 2
	vsetvli	s10, a7, e64, m1, ta, ma
	vlse64.v	v19, (a0), t0
	addi	s1, a0, 8
	sd	s1, 192(sp)                     # 8-byte Folded Spill
	vlse64.v	v12, (s1), t0
	addi	s1, a0, 16
	sd	s1, 184(sp)                     # 8-byte Folded Spill
	vlse64.v	v8, (s1), t0
	csrr	a6, vlenb
	slli	a6, a6, 1
	add	a6, a6, sp
	addi	a6, a6, 208
	vs1r.v	v8, (a6)                        # Unknown-size Folded Spill
	addi	s1, a0, 24
	sd	s1, 176(sp)                     # 8-byte Folded Spill
	vlse64.v	v17, (s1), t0
	addi	s1, a0, 32
	sd	s1, 168(sp)                     # 8-byte Folded Spill
	vlse64.v	v10, (s1), t0
	addi	s1, a0, 40
	sd	s1, 160(sp)                     # 8-byte Folded Spill
	vlse64.v	v11, (s1), t0
	addi	s1, a0, 48
	sd	s1, 152(sp)                     # 8-byte Folded Spill
	vlse64.v	v30, (s1), t0
	addi	s1, a0, 56
	sd	s1, 144(sp)                     # 8-byte Folded Spill
	vlse64.v	v14, (s1), t0
	addi	s1, a0, 64
	sd	s1, 136(sp)                     # 8-byte Folded Spill
	vlse64.v	v7, (s1), t0
	addi	s1, a0, 72
	sd	s1, 128(sp)                     # 8-byte Folded Spill
	vlse64.v	v25, (s1), t0
	addi	s1, a0, 80
	sd	s1, 120(sp)                     # 8-byte Folded Spill
	vlse64.v	v28, (s1), t0
	addi	s1, a0, 88
	sd	s1, 112(sp)                     # 8-byte Folded Spill
	vlse64.v	v18, (s1), t0
	addi	s1, a0, 96
	sd	s1, 104(sp)                     # 8-byte Folded Spill
	vlse64.v	v31, (s1), t0
	addi	s1, a0, 104
	sd	s1, 96(sp)                      # 8-byte Folded Spill
	vlse64.v	v23, (s1), t0
	addi	s1, a0, 112
	sd	s1, 88(sp)                      # 8-byte Folded Spill
	vlse64.v	v13, (s1), t0
	addi	s1, a0, 120
	sd	s1, 80(sp)                      # 8-byte Folded Spill
	vlse64.v	v16, (s1), t0
	addi	s1, a0, 128
	sd	s1, 72(sp)                      # 8-byte Folded Spill
	vlse64.v	v26, (s1), t0
	addi	s1, a0, 136
	sd	s1, 64(sp)                      # 8-byte Folded Spill
	vlse64.v	v20, (s1), t0
	addi	s1, a0, 144
	sd	s1, 56(sp)                      # 8-byte Folded Spill
	vlse64.v	v24, (s1), t0
	addi	s1, a0, 152
	sd	s1, 48(sp)                      # 8-byte Folded Spill
	vlse64.v	v0, (s1), t0
	addi	s1, a0, 160
	sd	s1, 40(sp)                      # 8-byte Folded Spill
	vlse64.v	v27, (s1), t0
	addi	s1, a0, 168
	sd	s1, 32(sp)                      # 8-byte Folded Spill
	vlse64.v	v22, (s1), t0
	addi	s11, a0, 176
	vlse64.v	v21, (s11), t0
	addi	ra, a0, 184
	vlse64.v	v29, (ra), t0
	addi	a6, a0, 192
	vlse64.v	v15, (a6), t0
	ld	s8, 24(sp)                      # 8-byte Folded Reload
.LBB0_2:                                #   Parent Loop BB0_1 Depth=1
                                        # =>  This Inner Loop Header: Depth=2
	addi	s1, sp, 208
	vs1r.v	v7, (s1)                        # Unknown-size Folded Spill
	csrr	s1, vlenb
	add	s1, s1, sp
	addi	s1, s1, 208
	vs1r.v	v16, (s1)                       # Unknown-size Folded Spill
	vsetvli	zero, s10, e64, m1, ta, ma
	vxor.vv	v1, v19, v11
	vxor.vv	v2, v16, v28
	vxor.vv	v1, v1, v2
	vxor.vv	v5, v1, v27
	vxor.vv	v1, v12, v30
	vxor.vv	v2, v26, v18
	vxor.vv	v1, v1, v2
	vxor.vv	v3, v1, v22
	vmv1r.v	v16, v13
	csrr	s1, vlenb
	slli	s1, s1, 1
	add	s1, s1, sp
	addi	s1, s1, 208
	vl1r.v	v13, (s1)                       # Unknown-size Folded Reload
	vxor.vv	v2, v20, v31
	vxor.vv	v1, v13, v14
	vxor.vv	v1, v1, v2
	vxor.vv	v4, v1, v21
	vxor.vv	v2, v24, v23
	vxor.vv	v1, v17, v7
	vxor.vv	v6, v1, v2
	vxor.vv	v1, v10, v25
	vxor.vv	v2, v0, v16
	vxor.vv	v1, v1, v2
	vxor.vv	v7, v1, v15

	vadd.vv	v1, v3, v3
	vsrl.vx	v2, v3, a5
	vxor.vv	v1, v1, v7
	vadd.vv	v1, v1, v2

	vadd.vv	v2, v4, v4
	vsrl.vx	v8, v4, a5
	vxor.vv	v2, v2, v5
	vadd.vv	v2, v2, v8

	vxor.vv	v8, v6, v29

	vadd.vv	v6, v8, v8
	vxor.vv	v3, v6, v3
	vsrl.vx	v6, v8, a5
	vadd.vv	v3, v3, v6

	vadd.vv	v6, v7, v7
	vxor.vv	v4, v6, v4
	vsrl.vx	v6, v7, a5
	vadd.vv	v4, v4, v6

	vadd.vv	v6, v5, v5
	vxor.vv	v8, v6, v8
	vsrl.vx	v5, v5, a5
	vadd.vv	v5, v8, v5
	
	vxor.vv	v8, v19, v1
	vxor.vv	v19, v30, v2
	vsll.vx	v30, v19, t5
	vsrl.vi	v19, v19, 20
	vadd.vv	v6, v30, v19
	vxor.vv	v19, v31, v3
	vsll.vx	v30, v19, t6
	vsrl.vi	v19, v19, 21
	vadd.vv	v19, v30, v19
	vxor.vv	v24, v24, v4
	vsll.vi	v30, v24, 21
	vsrl.vx	v24, v24, t6
	vxor.vv	v15, v15, v5
	vadd.vv	v24, v30, v24
	vsll.vi	v30, v15, 14
	vsrl.vx	v15, v15, t2
	vadd.vv	v7, v30, v15
	vnot.v	v15, v6
	vand.vv	v31, v15, v19
	vnot.v	v15, v24
	vand.vv	v15, v15, v7
	vxor.vv	v15, v19, v15
	vnot.v	v19, v19
	vand.vv	v9, v19, v24
	vnot.v	v19, v7
	vand.vv	v19, v19, v8
	vxor.vv	v30, v24, v19
	vxor.vv	v19, v8, v31
	vnot.v	v8, v8
	vand.vv	v8, v8, v6
	vxor.vv	v24, v7, v8
	vxor.vv	v8, v17, v4
	vxor.vv	v31, v6, v9
	vsll.vi	v9, v8, 28
	vsrl.vx	v8, v8, a3
	vadd.vv	v8, v9, v8
	vxor.vv	v9, v25, v5
	vsll.vi	v17, v9, 20
	vsrl.vx	v9, v9, t5
	vadd.vv	v9, v17, v9
	vxor.vv	v17, v28, v1
	vsll.vi	v25, v17, 3
	vsrl.vx	v17, v17, a2
	vadd.vv	v17, v25, v17
	vxor.vv	v25, v26, v2
	vsll.vx	v26, v25, t3
	vsrl.vi	v25, v25, 19
	vxor.vv	v21, v21, v3
	vadd.vv	v25, v26, v25
	vsll.vx	v26, v21, a2
	vsrl.vi	v21, v21, 3
	vadd.vv	v6, v26, v21
	vnot.v	v21, v9
	vand.vv	v26, v21, v17
	vnot.v	v21, v25
	vand.vv	v21, v21, v6
	vxor.vv	v28, v17, v21
	vnot.v	v21, v6
	vand.vv	v21, v21, v8
	vxor.vv	v26, v8, v26
	vnot.v	v8, v8
	vnot.v	v17, v17
	vand.vv	v8, v8, v9
	vand.vv	v17, v17, v25
	vxor.vv	v21, v25, v21
	vxor.vv	v25, v6, v8
	vxor.vv	v8, v12, v2
	vxor.vv	v17, v9, v17
	vadd.vv	v9, v8, v8
	vsrl.vx	v8, v8, a5
	vadd.vv	v8, v9, v8
	vxor.vv	v9, v14, v3
	vsll.vi	v12, v9, 6
	vsrl.vx	v9, v9, t4
	vadd.vv	v9, v12, v9
	vxor.vv	v12, v23, v4
	vsll.vi	v14, v12, 25
	vsrl.vx	v12, v12, a4
	vadd.vv	v14, v14, v12
	vxor.vv	v12, v0, v5
	vsll.vi	v23, v12, 8
	vsrl.vx	v12, v12, a1
	vadd.vv	v23, v23, v12
	vxor.vv	v12, v27, v1
	vsll.vi	v27, v12, 18
	vsrl.vx	v12, v12, s2
	vadd.vv	v27, v27, v12
	vnot.v	v12, v9
	vand.vv	v0, v12, v14
	vnot.v	v12, v23
	vand.vv	v12, v12, v27
	vxor.vv	v12, v14, v12
	vnot.v	v14, v14
	vand.vv	v6, v14, v23
	vnot.v	v14, v27
	vand.vv	v14, v14, v8
	vxor.vv	v23, v23, v14
	ld	s9, -8(s8)
	vxor.vv	v14, v8, v0
	vnot.v	v8, v8
	vand.vv	v8, v8, v9
	vxor.vv	v27, v27, v8
	vxor.vv	v8, v10, v5
	vxor.vv	v0, v9, v6
	vsll.vi	v9, v8, 27
	vsrl.vx	v8, v8, s3
	vadd.vv	v8, v9, v8
	vxor.vv	v9, v11, v1
	vsll.vx	v10, v9, a3
	vsrl.vi	v9, v9, 28
	vadd.vv	v9, v10, v9
	vxor.vv	v10, v18, v2
	vsll.vi	v11, v10, 10
	vsrl.vx	v10, v10, s4
	vadd.vv	v10, v11, v10
	vxor.vv	v11, v20, v3
	vsll.vi	v18, v11, 15
	vsrl.vx	v11, v11, s5
	vadd.vv	v11, v18, v11
	vxor.vv	v18, v29, v4
	vsll.vx	v20, v18, a1
	vsrl.vi	v18, v18, 8
	vadd.vv	v18, v20, v18
	vnot.v	v20, v9
	vand.vv	v29, v20, v10
	vnot.v	v20, v11
	vand.vv	v20, v20, v18
	vxor.vv	v20, v10, v20
	vnot.v	v10, v10
	vand.vv	v6, v10, v11
	vnot.v	v10, v18
	vand.vv	v10, v10, v8
	vxor.vv	v29, v8, v29
	vnot.v	v8, v8
	vand.vv	v8, v8, v9
	vxor.vv	v18, v18, v8
	vxor.vv	v10, v11, v10
	vxor.vv	v8, v13, v3
	vxor.vv	v11, v9, v6
	vsll.vx	v9, v8, s0
	vsrl.vi	v8, v8, 2
	vadd.vv	v8, v9, v8
	vxor.vx	v19, v19, s9
	addi	s1, sp, 208
	vl1r.v	v9, (s1)                        # Unknown-size Folded Reload
	vxor.vv	v9, v9, v4
	vsll.vx	v3, v9, s6
	vsrl.vi	v9, v9, 9
	vadd.vv	v3, v3, v9
	vxor.vv	v9, v16, v5
	vsll.vx	v13, v9, a4
	vsrl.vi	v9, v9, 25
	vadd.vv	v9, v13, v9
	csrr	s1, vlenb
	add	s1, s1, sp
	addi	s1, s1, 208
	vl1r.v	v13, (s1)                       # Unknown-size Folded Reload
	vxor.vv	v13, v13, v1
	vsll.vx	v16, v13, s7
	vsrl.vi	v13, v13, 23
	vadd.vv	v16, v16, v13
	vxor.vv	v13, v22, v2
	vsll.vi	v22, v13, 2
	vsrl.vx	v13, v13, s0
	vadd.vv	v1, v22, v13
	vnot.v	v2, v16
	vnot.v	v13, v3
	vand.vv	v2, v2, v1
	vnot.v	v22, v9
	vand.vv	v13, v13, v9
	vxor.vv	v9, v9, v2
	vnot.v	v2, v1
	vand.vv	v2, v2, v8
	vxor.vv	v13, v8, v13
	vnot.v	v8, v8
	vand.vv	v8, v8, v3
	vxor.vv	v8, v1, v8
	vxor.vv	v1, v31, v17
	vxor.vv	v1, v1, v0
	vand.vv	v22, v22, v16
	vxor.vv	v1, v1, v11
	vxor.vv	v16, v16, v2
	vxor.vv	v22, v3, v22
	vxor.vv	v2, v1, v22
	vxor.vv	v1, v15, v28
	vxor.vv	v1, v1, v12
	vxor.vv	v1, v1, v20
	vxor.vv	v4, v1, v9
	vxor.vv	v1, v30, v21
	vxor.vv	v1, v1, v23
	vxor.vv	v1, v1, v10
	vxor.vv	v5, v1, v16
	vsrl.vx	v3, v2, a5
	vadd.vv	v1, v2, v2
	vadd.vv	v1, v1, v3
	vadd.vv	v3, v4, v4
	vsrl.vx	v6, v4, a5
	vadd.vv	v6, v3, v6
	vsrl.vx	v7, v5, a5
	vadd.vv	v3, v5, v5
	vadd.vv	v3, v3, v7
	vxor.vv	v7, v24, v25
	vxor.vv	v7, v7, v27
	vxor.vv	v7, v7, v18
	vxor.vv	v7, v7, v8
	vxor.vv	v3, v3, v2
	vadd.vv	v2, v7, v7
	vxor.vv	v1, v1, v7
	vsrl.vx	v7, v7, a5
	vadd.vv	v7, v2, v7
	vxor.vv	v2, v19, v26
	vxor.vv	v2, v2, v14
	vxor.vv	v2, v2, v29
	vxor.vv	v2, v2, v13
	vxor.vv	v4, v7, v4
	vadd.vv	v7, v2, v2
	vxor.vv	v6, v6, v2
	vsrl.vx	v2, v2, a5
	vadd.vv	v2, v7, v2
	vxor.vv	v5, v2, v5
	vxor.vv	v17, v17, v6
	vxor.vv	v2, v19, v1
	vsll.vx	v19, v17, t5
	vsrl.vi	v17, v17, 20
	vadd.vv	v7, v19, v17
	vxor.vv	v12, v12, v3
	vsll.vx	v17, v12, t6
	vsrl.vi	v12, v12, 21
	vadd.vv	v12, v17, v12
	vxor.vv	v10, v10, v4
	vsll.vi	v17, v10, 21
	vsrl.vx	v10, v10, t6
	vadd.vv	v10, v17, v10
	vxor.vv	v8, v8, v5
	vsll.vi	v17, v8, 14
	vsrl.vx	v8, v8, t2
	vadd.vv	v8, v17, v8
	vnot.v	v17, v7
	ld	s1, 0(s8)
	vand.vv	v17, v17, v12
	vxor.vv	v19, v2, v17
	vsetvli	zero, zero, e64, m1, tu, ma
	vxor.vx	v19, v19, s1
	vsetvli	zero, zero, e64, m1, ta, ma
	vnot.v	v17, v10
	vand.vv	v17, v17, v8
	vxor.vv	v17, v12, v17
	csrr	s1, vlenb
	slli	s1, s1, 1
	add	s1, s1, sp
	addi	s1, s1, 208
	vs1r.v	v17, (s1)                       # Unknown-size Folded Spill
	vnot.v	v17, v8
	vand.vv	v17, v17, v2
	vnot.v	v12, v12
	vand.vv	v12, v12, v10
	vxor.vv	v17, v10, v17
	vnot.v	v10, v2
	vand.vv	v10, v10, v7
	vxor.vv	v10, v8, v10
	vxor.vv	v8, v30, v4

	vsll.vi	v30, v8, 28
	vsrl.vx	v8, v8, a3
	vadd.vv	v8, v30, v8
	vxor.vv	v25, v25, v5

	vsll.vi	v30, v25, 20
	vsrl.vx	v25, v25, t5
	vxor.vv	v14, v14, v1
	vadd.vv	v25, v30, v25
	vsll.vi	v30, v14, 3
	vsrl.vx	v14, v14, a2
	vadd.vv	v30, v30, v14
	vxor.vv	v11, v11, v6
	vsll.vx	v14, v11, t3
	vsrl.vi	v11, v11, 19
	vxor.vv	v9, v9, v3
	vadd.vv	v11, v14, v11
	vsll.vx	v14, v9, a2
	vsrl.vi	v9, v9, 3
	vadd.vv	v9, v14, v9
	vnot.v	v14, v25
	vand.vv	v2, v14, v30
	vnot.v	v14, v11
	vand.vv	v14, v14, v9
	vxor.vv	v12, v7, v12
	vnot.v	v7, v9
	vxor.vv	v14, v30, v14
	vand.vv	v7, v7, v8
	vnot.v	v30, v30
	vand.vv	v30, v30, v11
	vxor.vv	v7, v11, v7
	vxor.vv	v11, v8, v2
	vnot.v	v8, v8
	vand.vv	v8, v8, v25
	vxor.vv	v30, v25, v30
	vxor.vv	v25, v9, v8
	vxor.vv	v8, v31, v6
	vadd.vv	v9, v8, v8
	vsrl.vx	v8, v8, a5
	vadd.vv	v8, v9, v8
	vxor.vv	v9, v28, v3
	vsll.vi	v28, v9, 6
	vsrl.vx	v9, v9, t4
	vadd.vv	v9, v28, v9
	vxor.vv	v23, v23, v4
	vsll.vi	v28, v23, 25
	vsrl.vx	v23, v23, a4
	vadd.vv	v23, v28, v23
	vxor.vv	v18, v18, v5
	vsll.vi	v28, v18, 8
	vsrl.vx	v18, v18, a1
	vadd.vv	v18, v28, v18
	vxor.vv	v13, v13, v1
	vsll.vi	v28, v13, 18
	vsrl.vx	v13, v13, s2
	vadd.vv	v13, v28, v13
	vnot.v	v31, v18
	vnot.v	v28, v9
	vand.vv	v31, v31, v13
	vand.vv	v28, v28, v23
	vxor.vv	v31, v23, v31
	vnot.v	v23, v23
	vand.vv	v2, v23, v18
	vnot.v	v23, v13
	vand.vv	v23, v23, v8
	vxor.vv	v28, v8, v28
	vnot.v	v8, v8
	vand.vv	v8, v8, v9
	vxor.vv	v13, v13, v8
	vxor.vv	v23, v18, v23
	vxor.vv	v8, v24, v5
	vxor.vv	v18, v9, v2
	vsll.vi	v9, v8, 27
	vsrl.vx	v8, v8, s3
	vadd.vv	v8, v9, v8
	vxor.vv	v9, v26, v1
	vsll.vx	v24, v9, a3
	vsrl.vi	v9, v9, 28
	vadd.vv	v9, v24, v9
	vxor.vv	v24, v0, v6
	vsll.vi	v26, v24, 10
	vsrl.vx	v24, v24, s4
	vadd.vv	v24, v26, v24
	vxor.vv	v20, v20, v3
	vsll.vi	v26, v20, 15
	vsrl.vx	v20, v20, s5
	vadd.vv	v26, v26, v20
	vxor.vv	v16, v16, v4
	vsll.vx	v20, v16, a1
	vsrl.vi	v16, v16, 8
	vadd.vv	v0, v20, v16
	vnot.v	v20, v26
	vnot.v	v16, v9
	vand.vv	v20, v20, v0
	vand.vv	v16, v16, v24
	vxor.vv	v20, v24, v20
	vnot.v	v24, v24
	vand.vv	v2, v24, v26
	vnot.v	v24, v0
	vand.vv	v24, v24, v8
	vxor.vv	v16, v8, v16
	vnot.v	v8, v8
	vand.vv	v8, v8, v9
	vxor.vv	v0, v0, v8
	vxor.vv	v24, v26, v24
	vxor.vv	v8, v15, v3
	vxor.vv	v26, v9, v2
	vsll.vx	v9, v8, s0
	vsrl.vi	v8, v8, 2
	vadd.vv	v8, v9, v8
	vxor.vv	v9, v21, v4
	vsll.vx	v15, v9, s6
	vsrl.vi	v9, v9, 9
	vadd.vv	v9, v15, v9
	vxor.vv	v15, v27, v5
	vsll.vx	v21, v15, a4
	vsrl.vi	v15, v15, 25
	vadd.vv	v15, v21, v15
	vxor.vv	v21, v29, v1
	vsll.vx	v27, v21, s7
	vsrl.vi	v21, v21, 23
	vadd.vv	v27, v27, v21
	vxor.vv	v21, v22, v6
	vsll.vi	v22, v21, 2
	vsrl.vx	v21, v21, s0
	vadd.vv	v1, v22, v21
	vnot.v	v21, v9
	vand.vv	v22, v21, v15
	vnot.v	v21, v15
	vand.vv	v2, v21, v27
	vnot.v	v21, v27
	vand.vv	v21, v21, v1
	vxor.vv	v21, v15, v21
	vnot.v	v15, v1
	vand.vv	v15, v15, v8
	vxor.vv	v29, v27, v15
	vxor.vv	v27, v8, v22
	vnot.v	v8, v8
	vand.vv	v8, v8, v9
	vxor.vv	v22, v9, v2
	addi	s8, s8, 16
	addi	s1, t1, 200
	vxor.vv	v15, v1, v8
	bne	s8, s1, .LBB0_2
# %bb.3:                                #   in Loop: Header=BB0_1 Depth=1
	vsse64.v	v19, (a0), t0
	ld	s1, 192(sp)                     # 8-byte Folded Reload
	vsse64.v	v12, (s1), t0
	csrr	s1, vlenb
	slli	s1, s1, 1
	add	s1, s1, sp
	addi	s1, s1, 208
	vl1r.v	v8, (s1)                        # Unknown-size Folded Reload
	ld	s1, 184(sp)                     # 8-byte Folded Reload
	vsse64.v	v8, (s1), t0
	ld	s1, 176(sp)                     # 8-byte Folded Reload
	vsse64.v	v17, (s1), t0
	ld	s1, 168(sp)                     # 8-byte Folded Reload
	vsse64.v	v10, (s1), t0
	ld	s1, 160(sp)                     # 8-byte Folded Reload
	vsse64.v	v11, (s1), t0
	ld	s1, 152(sp)                     # 8-byte Folded Reload
	vsse64.v	v30, (s1), t0
	ld	s1, 144(sp)                     # 8-byte Folded Reload
	vsse64.v	v14, (s1), t0
	ld	s1, 136(sp)                     # 8-byte Folded Reload
	vsse64.v	v7, (s1), t0
	ld	s1, 128(sp)                     # 8-byte Folded Reload
	vsse64.v	v25, (s1), t0
	ld	s1, 120(sp)                     # 8-byte Folded Reload
	vsse64.v	v28, (s1), t0
	ld	s1, 112(sp)                     # 8-byte Folded Reload
	vsse64.v	v18, (s1), t0
	ld	s1, 104(sp)                     # 8-byte Folded Reload
	vsse64.v	v31, (s1), t0
	ld	s1, 96(sp)                      # 8-byte Folded Reload
	vsse64.v	v23, (s1), t0
	ld	s1, 88(sp)                      # 8-byte Folded Reload
	vsse64.v	v13, (s1), t0
	ld	s1, 80(sp)                      # 8-byte Folded Reload
	vsse64.v	v16, (s1), t0
	ld	s1, 72(sp)                      # 8-byte Folded Reload
	vsse64.v	v26, (s1), t0
	ld	s1, 64(sp)                      # 8-byte Folded Reload
	vsse64.v	v20, (s1), t0
	ld	s1, 56(sp)                      # 8-byte Folded Reload
	vsse64.v	v24, (s1), t0
	ld	s1, 48(sp)                      # 8-byte Folded Reload
	vsse64.v	v0, (s1), t0
	ld	s1, 40(sp)                      # 8-byte Folded Reload
	vsse64.v	v27, (s1), t0
	ld	s1, 32(sp)                      # 8-byte Folded Reload
	vsse64.v	v22, (s1), t0
	vsse64.v	v21, (s11), t0
	vsse64.v	v29, (ra), t0
	vsse64.v	v15, (a6), t0
	sub	a7, a7, s10
	mul	s1, s10, t0
	add	a0, a0, s1
	bnez	a7, .LBB0_1
# %bb.4:
	csrr	a0, vlenb
	slli	a0, a0, 2
	add	sp, sp, a0
	ld	ra, 312(sp)                     # 8-byte Folded Reload
	ld	s0, 304(sp)                     # 8-byte Folded Reload
	ld	s1, 296(sp)                     # 8-byte Folded Reload
	ld	s2, 288(sp)                     # 8-byte Folded Reload
	ld	s3, 280(sp)                     # 8-byte Folded Reload
	ld	s4, 272(sp)                     # 8-byte Folded Reload
	ld	s5, 264(sp)                     # 8-byte Folded Reload
	ld	s6, 256(sp)                     # 8-byte Folded Reload
	ld	s7, 248(sp)                     # 8-byte Folded Reload
	ld	s8, 240(sp)                     # 8-byte Folded Reload
	ld	s9, 232(sp)                     # 8-byte Folded Reload
	ld	s10, 224(sp)                    # 8-byte Folded Reload
	ld	s11, 216(sp)                    # 8-byte Folded Reload
	addi	sp, sp, 320
	ret
.Lfunc_end0:
	.size	KeccakP1600_StatePermute_x4_vector, .Lfunc_end0-KeccakP1600_StatePermute_x4_vector
	.cfi_endproc
                                        # -- End function
	.globl	KeccakP1600_StatePermute_x4_vector_wrapper # -- Begin function KeccakP1600_StatePermute_x4_vector_wrapper
	.p2align	1
	.type	KeccakP1600_StatePermute_x4_vector_wrapper,@function
KeccakP1600_StatePermute_x4_vector_wrapper: # @KeccakP1600_StatePermute_x4_vector_wrapper
	.cfi_startproc
# %bb.0:
	tail	KeccakP1600_StatePermute_x4_vector
.Lfunc_end1:
	.size	KeccakP1600_StatePermute_x4_vector_wrapper, .Lfunc_end1-KeccakP1600_StatePermute_x4_vector_wrapper
	.cfi_endproc
                                        # -- End function
	.type	RC,@object                      # @RC
	.section	.rodata,"a",@progbits
	.p2align	3, 0x0
RC:
	.quad	1                               # 0x1
	.quad	32898                           # 0x8082
	.quad	-9223372036854742902            # 0x800000000000808a
	.quad	-9223372034707259392            # 0x8000000080008000
	.quad	32907                           # 0x808b
	.quad	2147483649                      # 0x80000001
	.quad	-9223372034707259263            # 0x8000000080008081
	.quad	-9223372036854743031            # 0x8000000000008009
	.quad	138                             # 0x8a
	.quad	136                             # 0x88
	.quad	2147516425                      # 0x80008009
	.quad	2147483658                      # 0x8000000a
	.quad	2147516555                      # 0x8000808b
	.quad	-9223372036854775669            # 0x800000000000008b
	.quad	-9223372036854742903            # 0x8000000000008089
	.quad	-9223372036854743037            # 0x8000000000008003
	.quad	-9223372036854743038            # 0x8000000000008002
	.quad	-9223372036854775680            # 0x8000000000000080
	.quad	32778                           # 0x800a
	.quad	-9223372034707292150            # 0x800000008000000a
	.quad	-9223372034707259263            # 0x8000000080008081
	.quad	-9223372036854742912            # 0x8000000000008080
	.quad	2147483649                      # 0x80000001
	.quad	2147516424                      # 0x80008008
	.size	RC, 192

	.ident	"Ubuntu clang version 18.1.3 (1ubuntu1)"
	.section	".note.GNU-stack","",@progbits
	.addrsig
